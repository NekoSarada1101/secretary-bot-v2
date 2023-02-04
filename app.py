import os
import sys
import requests
import logging
import json
import random
import openai
from datetime import datetime, timedelta
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request
from twitch import bp
from google.cloud import firestore, secretmanager, bigquery


# constant ============================================
secret_client = secretmanager.SecretManagerServiceClient()
firestore_client = firestore.Client()
bq_client = bigquery.Client()

SLACK_BOT_TOKEN = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_BOT_TOKEN/versions/latest'}).payload.data.decode('UTF-8')
SLACK_SIGNING_SECRET = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_SIGNING_SECRET/versions/latest'}).payload.data.decode('UTF-8')
TWITCH_CLIENT_ID = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_ID/versions/latest'}).payload.data.decode('UTF-8')
TWITCH_CLIENT_SECRET = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_SECRET/versions/latest'}).payload.data.decode('UTF-8')
USER_ID = os.environ.get('USER_ID')
TWITCH_SLACK_CHANNEL_ID = os.environ.get('TWITCH_SLACK_CHANNEL_ID')
GCP_NOTICE_SLACK_CHANNEL_ID = os.environ.get('GCP_NOTICE_SLACK_CHANNEL_ID')
TABLE_ID = os.environ.get('TABLE_ID')

flask_app = Flask(__name__)
flask_app.register_blueprint(bp)
bolt_app = App(token=SLACK_BOT_TOKEN, signing_secret=SLACK_SIGNING_SECRET)
handler = SlackRequestHandler(bolt_app)

global_log_fields = {}


# logger ===============================================
def get_trace_header(request):
    request_is_defined = "request" in globals() or "request" in locals()
    if request_is_defined and request:
        trace_header = request.headers.get("X-Cloud-Trace-Context")

        if trace_header and 'slackbot-288310':
            trace = trace_header.split("/")
            global_log_fields[
                "logging.googleapis.com/trace"
            ] = f"projects/slackbot-288310/traces/{trace[0]}"


class JsonFormatter(logging.Formatter):
    def format(self, log):
        return json.dumps({
            'level': log.levelname,
            'message': log.getMessage(),
            **global_log_fields,
        })


formatter = JsonFormatter()
stream = logging.StreamHandler(stream=sys.stdout)
stream.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(stream)


# functions ==========================================
@bolt_app.event("app_mention")
def response_message(event, ack, say):
    ack()
    logger.info('===== START text-davinci-003 mention response =====')
    logger.info('request={}'.format(event))

    try:
        logger.info('----- get openai chat response text')
        openai.api_key = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/OPENAI_API_KEY/versions/latest'}).payload.data.decode('UTF-8')

        logger.info('----- get firestore openai chat history -----')
        doc_ref_event = firestore_client.collection('secretary_bot_v2').document('openai')
        history = doc_ref_event.get().to_dict()['history']

        prompt = history + event['text'][14:].strip(' ')

        response = openai.Completion.create(
            model='text-davinci-003',
            prompt=prompt,
            temperature=0,  # ランダム性の制御[0-1]
            max_tokens=1000,  # 返ってくるレスポンストークンの最大数
            top_p=1.0,  # 多様性の制御[0-1]
            frequency_penalty=1.0,  # 周波数制御[0-2]：高いと同じ話題を繰り返さなくなる
            presence_penalty=1.0  # 新規トピック制御[0-2]：高いと新規のトピックが出現しやすくなる
        )
        logger.info('response={}'.format(response))
        texts = ''.join([choice['text'] for choice in response.choices])

        logger.info('----- update firestore openai chat history -----')
        firestore_client.collection('secretary_bot_v2').document('openai').update({'history': prompt + texts + '\n\n'})

        blocks = [
            {
                "type": "section",
                "text": {
                        "type": "mrkdwn",
                        "text": '<@{}> {}'.format(event["user"], texts.strip('\n'))
                }
            }
        ]

        logger.info('----- slack send chat message -----')
        payload = {
            'blocks': blocks,
            'icon_emoji': ':secretary:',
        }
        logger.info('payload={}'.format(payload))
        say(payload)

    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END text-davinci-003 mention response =====')


@ flask_app.route('/gcp/notify_gcp_cost', methods=['POST'])
def notify_gcp_cost():
    get_trace_header(request)

    logger.info('===== START notify gcp cost =====')
    logger.info('request={}'.format(request.get_data()))

    try:
        logger.info('----- get bigquery gcp cost top 3 -----')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        top_query = """
            SELECT service.description as service, sku.description as sku, SUM(cost) AS cost
            FROM `{}`
            WHERE project.id = 'slackbot-288310' AND FORMAT_DATE('%Y-%m-%d',usage_start_time) = '{}'
            GROUP BY service, sku
            HAVING cost != 0
            ORDER BY cost desc
            LIMIT 3
        """.format(TABLE_ID, yesterday)
        logger.info('top_query={}'.format(top_query))

        query_job = bq_client.query(top_query)
        top_query_result = []
        for row in query_job:
            top_query_result.append({'service': row['service'], 'sku': row['sku'], 'cost': row['cost']})
        logger.info('top_query_result={}'.format(top_query_result))

        logger.info('----- get bigquery gcp cost total -----')
        total_query = """
            SELECT SUM(cost) AS cost
            FROM `{}`
            WHERE project.id = 'slackbot-288310' AND FORMAT_DATE('%Y-%m-%d',usage_start_time) = '{}'
        """.format(TABLE_ID, yesterday)
        logger.info('top_query={}'.format(total_query))

        query_job = bq_client.query(total_query)
        total_query_result = None
        for row in query_job:
            total_query_result = row['cost']
        logger.info('total_query_result={}'.format(total_query_result))

        logger.info('----- POST slack api send chat message -----')
        color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])

        attachment = [{
            'color': color,
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': '*{} Total Cost*\n{} JPY'.format(yesterday, total_query_result)
                    }
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text':
                        f'*{yesterday} Cost Top3*\n*{top_query_result[0]["service"]} : {top_query_result[0]["sku"]}*\n{top_query_result[0]["cost"]} JPY\n\n*{top_query_result[1]["service"]} : {top_query_result[1]["sku"]}*\n{top_query_result[1]["cost"]} JPY\n\n*{top_query_result[2]["service"]} : {top_query_result[2]["sku"]}*\n{top_query_result[2]["cost"]} JPY'
                    }
                }
            ]
        }]

        payload = {
            'token': SLACK_BOT_TOKEN,
            'channel': GCP_NOTICE_SLACK_CHANNEL_ID,
            'text': 'Notify Today GCP Cost',
            'attachments': json.dumps(attachment),
            'username': 'Notify GCP Cost',
            'icon_emoji': ':gcp:',
        }
        logger.info('payload={}'.format(payload))

        response = requests.post('https://slack.com/api/chat.postMessage', data=payload)
        logger.info('response={}'.format(response.text))

        return 'notify gcp cost success!', 204

    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END notify gcp cost =====')


@ bolt_app.command('/openai')
def openai(ack, say, command):
    ack()
    logger.info('===== START slash command /openai =====')
    logger.info('request={}'.format(command))

    values = command['text'].split(' ')

    try:
        if values[0] == 'reset':
            logger.info('----- update firestore openai chat history -----')
            firestore_client.collection('secretary_bot_v2').document('openai').update({'history': ''})

            say('reset openai chat history')
    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END slash command /openai =====')


@bolt_app.message('hello')
def message_hello(message, say):
    logger.info('request={}'.format(message))
    say(f'Hey there <@{message["user"]}>!')


@ bolt_app.command('/test')
def test(ack, say, command):
    ack()
    logger.info('request={}'.format(command))
    say('OK!')


@ bolt_app.event("message")  # ロギング
def handle_message_events(body, logger):
    logger.info(body)


@ flask_app.route('/', methods=['POST'])
def index():
    get_trace_header(request)
    logger.info('request={}'.format(request.get_data()))
    return 'Flask Test'


@ flask_app.route('/slack/events', methods=['POST'])
def slack_events():
    get_trace_header(request)
    return handler.handle(request)


if __name__ == '__main__':
    flask_app.run(port=int(os.environ.get('PORT', 3000)))
