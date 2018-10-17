import datetime
import hashlib
import hmac
import json
import urllib

from jupyterhub.spawner import (
    Spawner,
)
from tornado import (
    gen,
)
from tornado.concurrent import (
    Future,
)
from tornado.httpclient import (
    AsyncHTTPClient,
    HTTPError,
    HTTPRequest,
)
from traitlets import (
    Bool,
    Int,
    List,
    Unicode,
)


class FargateSpawner(Spawner):

    aws_region = Unicode(config=True)
    aws_host = Unicode(config=True)
    aws_access_key_id = Unicode(config=True)
    aws_secret_access_key = Unicode(config=True)
    task_cluster_name = Unicode(config=True)
    task_container_name = Unicode(config=True)
    task_definition_arn = Unicode(config=True)
    task_security_groups = List(trait=Unicode, config=True)
    task_subnets = List(trait=Unicode, config=True)
    notebook_port = Int(config=True)
    notebook_scheme = Unicode(config=True)
    notebook_args = List(trait=Unicode, config=True)

    task_arn = Unicode('')

    # We mostly are able to call the AWS API to determine status. However, when we yield the
    # event loop to create the task, if there is a poll before the creation is complete,
    # we must behave as though we are running/starting, but we have no IDs to use with which
    # to check the task.
    calling_run_task = Bool(False)

    progress_buffer = None

    def load_state(self, state):
        ''' Misleading name: this "loads" the state onto self, to be used by other methods '''

        super().load_state(state)

        # Called when first created: we might have no state from a previous invocation
        self.task_arn = state.get('task_arn', '')

    def get_state(self):
        ''' Misleading name: the return value of get_state is saved to the database in order
        to be able to restore after the hub went down '''

        state = super().get_state()
        state['task_arn'] = self.task_arn

        return state

    async def poll(self):
        # Return values, as dictacted by the Jupyterhub framework:
        # 0                   == not running, or not starting up, i.e. we need to call start
        # None                == running, or not finished starting
        # 1, or anything else == error

        return \
            None if self.calling_run_task else \
            0 if self.task_arn == '' else \
            None if (await _get_task_status(self.log, self._aws_endpoint(), self.task_cluster_name, self.task_arn)) in ALLOWED_STATUSES else \
            1

    async def start(self):
        self.log.debug('Starting spawner')
        self.progress_buffer = AsyncIteratorBuffer()

        task_port = self.notebook_port

        self.progress_buffer.write({'progress': 0.5, 'message': 'Starting server...'})
        try:
            self.calling_run_task = True
            args = ['--debug', '--port=' + str(task_port)] + self.notebook_args
            run_response = await _run_task(
                self.log, self._aws_endpoint(),
                self.task_cluster_name, self.task_container_name, self.task_definition_arn,
                self.task_security_groups, self.task_subnets,
                self.cmd + args, self.get_env())
            task_arn = run_response['tasks'][0]['taskArn']
            self.progress_buffer.write({'progress': 1})
        finally:
            self.calling_run_task = False

        self.task_arn = task_arn

        max_polls = 50
        num_polls = 0
        task_ip = ''
        while task_ip == '':
            num_polls += 1
            if num_polls >= max_polls:
                raise Exception('Task {} took too long to find IP address'.format(self.task_arn))

            task_ip = await _get_task_ip(self.log, self._aws_endpoint(), self.task_cluster_name, task_arn)
            await gen.sleep(1)
            self.progress_buffer.write({'progress': 1 + num_polls / max_polls})

        self.progress_buffer.write({'progress': 2})

        max_polls = self.start_timeout
        num_polls = 0
        status = ''
        while status != 'RUNNING':
            num_polls += 1
            if num_polls >= max_polls:
                raise Exception('Task {} took too long to become running'.format(self.task_arn))

            status = await _get_task_status(self.log, self._aws_endpoint(), self.task_cluster_name, task_arn)
            if status not in ALLOWED_STATUSES:
                raise Exception('Task {} is {}'.format(self.task_arn, status))

            await gen.sleep(1)
            self.progress_buffer.write({'progress': 2 + num_polls / max_polls * 98})

        self.progress_buffer.write({'progress': 100, 'message': 'Server started'})
        await gen.sleep(1)

        self.progress_buffer.close()

        return f'{self.notebook_scheme}://{task_ip}:{task_port}'

    async def stop(self, now=False):
        if self.task_arn == '':
            return

        self.log.debug('Stopping task (%s)...', self.task_arn)
        await _stop_task(self.log, self._aws_endpoint(), self.task_cluster_name, self.task_arn)
        self.log.debug('Stopped task (%s)... (done)', self.task_arn)

    def clear_state(self):
        super().clear_state()
        self.log.debug('Clearing state: (%s)', self.task_arn)
        self.task_arn = ''

    async def progress(self):
        async for progress_message in self.progress_buffer:
            yield progress_message

    def _aws_endpoint(self):
        return {
            'region': self.aws_region,
            'host': self.aws_host,
            'access_key_id': self.aws_access_key_id,
            'secret_access_key': self.aws_secret_access_key,
        }


ALLOWED_STATUSES = ('', 'PROVISIONING', 'PENDING', 'RUNNING')


async def _stop_task(logger, aws_endpoint, task_cluster_name, task_arn):
    return await _make_ecs_request(logger, aws_endpoint, 'StopTask', {
        'cluster': task_cluster_name,
        'task': task_arn
    })


async def _get_task_ip(logger, aws_endpoint, task_cluster_name, task_arn):
    described_task = await _describe_task(logger, aws_endpoint, task_cluster_name, task_arn)

    ip_address_attachements = [
        attachment['value']
        for attachment in described_task['attachments'][0]['details']
        if attachment['name'] == 'privateIPv4Address'
    ] if described_task and 'attachments' in described_task and described_task['attachments'] else []
    ip_address = ip_address_attachements[0] if ip_address_attachements else ''
    return ip_address


async def _get_task_status(logger, aws_endpoint, task_cluster_name, task_arn):
    described_task = await _describe_task(logger, aws_endpoint, task_cluster_name, task_arn)
    status = described_task['lastStatus'] if described_task else ''
    return status


async def _describe_task(logger, aws_endpoint, task_cluster_name, task_arn):
    described_tasks = await _make_ecs_request(logger, aws_endpoint, 'DescribeTasks', {
        'cluster': task_cluster_name,
        'tasks': [task_arn]
    })

    # Very strangely, sometimes 'tasks' is returned, sometimes 'task'
    # Also, creating a task seems to be eventually consistent, so it might
    # not be present at all
    task = \
        described_tasks['tasks'][0] if 'tasks' in described_tasks and described_tasks['tasks'] else \
        described_tasks['task'] if 'task' in described_tasks else \
        None
    return task


async def _run_task(logger, aws_endpoint,
                    task_cluster_name, task_container_name, task_definition_arn, task_security_groups, task_subnets,
                    task_command_and_args, task_env):
    return await _make_ecs_request(logger, aws_endpoint, 'RunTask', {
        'cluster': task_cluster_name,
        'taskDefinition': task_definition_arn,
        'overrides': {
            'containerOverrides': [{
                'command': task_command_and_args,
                'environment': [
                    {
                        'name': name,
                        'value': value,
                    } for name, value in task_env.items()
                ],
                'name': task_container_name,
            }],
        },
        'count': 1,
        'launchType': 'FARGATE',
        'networkConfiguration': {
            'awsvpcConfiguration': {
                'assignPublicIp': 'DISABLED',
                'securityGroups': task_security_groups,
                'subnets': task_subnets,
            },
        },
    })


async def _make_ecs_request(logger, aws_endpoint, target, dict_data):
    service = 'ecs'
    body = json.dumps(dict_data).encode('utf-8')
    headers = {
        'X-Amz-Target': f'AmazonEC2ContainerServiceV20141113.{target}',
        'Content-Type': 'application/x-amz-json-1.1',
    }
    path = '/'
    auth_headers = _aws_auth_headers(service, aws_endpoint, 'POST', path, {}, headers, body)
    client = AsyncHTTPClient()
    url = f'https://{aws_endpoint["host"]}{path}'
    request = HTTPRequest(url, method='POST', headers={**headers, **auth_headers}, body=body)
    logger.debug('Making request (%s)', body)
    try:
        response = await client.fetch(request)
    except HTTPError as exception:
        logger.exception('HTTPError from ECS (%s)', exception.response.body)
        raise
    logger.debug('Request response (%s)', response.body)
    return json.loads(response.body)


def _aws_auth_headers(service, aws_endpoint, method, path, query, headers, payload):
    algorithm = 'AWS4-HMAC-SHA256'

    now = datetime.datetime.utcnow()
    amzdate = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')
    credential_scope = f'{datestamp}/{aws_endpoint["region"]}/{service}/aws4_request'
    headers_lower = {
        header_key.lower().strip(): header_value.strip()
        for header_key, header_value in headers.items()
    }
    signed_header_keys = sorted([header_key
                                 for header_key in headers_lower.keys()] + ['host', 'x-amz-date'])
    signed_headers = ';'.join([header_key for header_key in signed_header_keys])
    payload_hash = hashlib.sha256(payload).hexdigest()

    def signature():
        def canonical_request():
            header_values = {
                **headers_lower,
                'host': aws_endpoint['host'],
                'x-amz-date': amzdate,
            }

            canonical_uri = urllib.parse.quote(path, safe='/~')
            query_keys = sorted(query.keys())
            canonical_querystring = '&'.join([
                urllib.parse.quote(key, safe='~') + '=' + urllib.parse.quote(query[key], safe='~')
                for key in query_keys
            ])
            canonical_headers = ''.join([
                header_key + ':' + header_values[header_key] + '\n'
                for header_key in signed_header_keys
            ])

            return f'{method}\n{canonical_uri}\n{canonical_querystring}\n' + \
                   f'{canonical_headers}\n{signed_headers}\n{payload_hash}'

        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        string_to_sign = \
            f'{algorithm}\n{amzdate}\n{credential_scope}\n' + \
            hashlib.sha256(canonical_request().encode('utf-8')).hexdigest()

        date_key = sign(('AWS4' + aws_endpoint['secret_access_key']).encode('utf-8'), datestamp)
        region_key = sign(date_key, aws_endpoint['region'])
        service_key = sign(region_key, service)
        request_key = sign(service_key, 'aws4_request')
        return sign(request_key, string_to_sign).hex()

    return {
        'x-amz-date': amzdate,
        'x-amz-content-sha256': payload_hash,
        'Authorization': (
            f'{algorithm} Credential={aws_endpoint["access_key_id"]}/{credential_scope}, ' +
            f'SignedHeaders={signed_headers}, Signature=' + signature()
        ),
    }


class AsyncIteratorBuffer:
    # The progress streaming endpoint may be requested multiple times, so each
    # call to `__aiter__` must return an iterator that starts from the first message

    class _Iterator:
        def __init__(self, parent):
            self.parent = parent
            self.cursor = 0

        async def __anext__(self):
            future = self.parent.futures[self.cursor]
            self.cursor += 1
            return await future

    def __init__(self):
        self.futures = [Future()]

    def __aiter__(self):
        return self._Iterator(self)

    def close(self):
        self.futures[-1].set_exception(StopAsyncIteration())

    def write(self, item):
        self.futures[-1].set_result(item)
        self.futures.append(Future())
