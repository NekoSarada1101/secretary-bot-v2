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
from google.cloud import firestore, secretmanager, bigquery


# constant ============================================
secret_client = secretmanager.SecretManagerServiceClient()
firestore_client = firestore.Client()
bq_client = bigquery.Client()

SLACK_BOT_TOKEN = secret_client.access_secret_version(
    request={
        'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_BOT_TOKEN/versions/latest'}
).payload.data.decode('UTF-8')
SLACK_SIGNING_SECRET = secret_client.access_secret_version(
    request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_SIGNING_SECRET/versions/latest'}
).payload.data.decode('UTF-8')
TWITCH_CLIENT_ID = secret_client.access_secret_version(
    request={
        'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_ID/versions/latest'}
).payload.data.decode('UTF-8')
TWITCH_CLIENT_SECRET = secret_client.access_secret_version(
    request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_SECRET/versions/latest'}
).payload.data.decode('UTF-8')
USER_ID = os.environ.get('USER_ID')
TWITCH_SLACK_CHANNEL_ID = os.environ.get('TWITCH_SLACK_CHANNEL_ID')
GCP_NOTICE_SLACK_CHANNEL_ID = os.environ.get('GCP_NOTICE_SLACK_CHANNEL_ID')
TABLE_ID = os.environ.get('TABLE_ID')
TWITCH_API_URL = 'https://api.twitch.tv'

flask_app = Flask(__name__)
bolt_app = App(token=SLACK_BOT_TOKEN, signing_secret=SLACK_SIGNING_SECRET)
handler = SlackRequestHandler(bolt_app)


# logger ===============================================
global_log_fields = {}


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
def get_firestore_twitch_token():
    logger.info('----- get firestore twitch token -----')
    doc_ref = firestore_client.collection('secretary_bot_v2').document('twitch')
    twitch_oauth_access_token = doc_ref.get().to_dict()['oauth_access_token']
    twitch_oauth_refresh_token = doc_ref.get().to_dict()['oauth_refresh_token']
    return twitch_oauth_access_token, twitch_oauth_refresh_token


def get_twitch_user_info(twitch_oauth_access_token, user_id):
    logger.info('----- GET twitch api get user info -----')
    headers = twitch_api_header(twitch_oauth_access_token)
    user_info = requests.get(f'{TWITCH_API_URL}/helix/users?id={user_id}', headers=headers).json()
    logger.info(f'response={user_info}')
    return user_info


def twitch_api_header(twitch_token):
    headers = {
        'Authorization': f'Bearer {twitch_token}',
        'Client-Id': TWITCH_CLIENT_ID,
        'Content-Type': 'application/json',
    }
    return headers


def post_slack_message(channel_id, text, attachments, username, icon_emoji):
    logger.info('----- POST slack api send chat message -----')
    payload = {
        'token': SLACK_BOT_TOKEN,
        'channel': channel_id,
        'text': text,
        'attachments': attachments,
        'username': username,
        'icon_emoji': icon_emoji,
    }
    logger.info(f'payload={payload}')

    response = requests.post('https://slack.com/api/chat.postMessage', data=payload)
    logger.info(f'response={response.text}')
    return response


@bolt_app.command('/twitch')
def twitch(ack, say, command):
    ack()
    logger.info('===== START slash command /twitch =====')
    logger.info(f'request={command}')

    try:
        validate_twitch_access_token()
        twitch_oauth_access_token = get_firestore_twitch_token()[0]

        values = command['text'].split(' ')

        if values[0] == 'now':
            logger.info('===== START get now on streaming list =====')
            logger.info('----- GET twitch api get follow list -----')
            headers = twitch_api_header(twitch_oauth_access_token)
            follow_info = requests.get(
                f'{TWITCH_API_URL}/helix/streams/followed?user_id={USER_ID}', headers=headers).json()
            logger.info(f'response={follow_info}')

            attachments = []
            for res in follow_info['data']:
                user_info = get_twitch_user_info(twitch_oauth_access_token, user_id=res["user_id"])

                color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])
                started_at = datetime.strptime(res['started_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%m月%d日 %H時%M分')

                attachment = {
                    'color': color,
                    'blocks': [
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'*{res["user_name"]}*'
                            }
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'<https://www.twitch.tv/{res["user_login"]}|{res["title"]}>'
                            }
                        },
                        {
                            'type': 'section',
                            'fields': [
                                {
                                    'type': 'mrkdwn',
                                    'text': '*Playing*'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': '*Started at*'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': res['game_name']
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': started_at
                                }
                            ],
                            'accessory': {
                                'type': 'image',
                                'image_url': user_info['data'][0]['profile_image_url'],
                                'alt_text': res['user_name']
                            }
                        }
                    ]
                }
                attachments.append(attachment)

            logger.info('----- slack send chat message -----')
            payload = {
                'text': 'Twitch Now On Stream',
                'attachments': attachments,
                'username': 'Twitch',
                'icon_emoji': ':twitch:',
            }
            logger.info(f'payload={payload}')
            say(payload)

        elif values[0] == 'sub':
            logger.info('===== START set event subscription =====')
            logger.info('----- GET twitch api get user info -----')
            headers = twitch_api_header(twitch_oauth_access_token)
            user_info = requests.get(f'{TWITCH_API_URL}/helix/users?login={values[1]}', headers=headers).json()
            logger.info(f'response={user_info}')

            logger.info('----- POST twitch api get app access token -----')
            token_info = requests.post(
                f'https://id.twitch.tv/oauth2/token?client_id={TWITCH_CLIENT_ID}'
                f'&client_secret={TWITCH_CLIENT_SECRET}&grant_type=client_credentials'
            ).json()
            logger.info(f'response={token_info}')

            set_twitch_subscription('channel.online', user_info, token_info, say)
            set_twitch_subscription('channel.update', user_info, token_info, say)
            set_twitch_subscription('channel.offline', user_info, token_info, say)

            logger.info('----- update firestore twitch streaming status -----')
            firestore_client.collection('secretary_bot_v2').document(
                'twitch_streaming').update({user_info['data'][0]['login']: False})
            logger.info('===== END set event subscription =====')

    except Exception as e:
        logger.error(e)
        say('エラーが発生しました。ログを確認してください。')
    finally:
        logger.info('===== END slash command /twitch =====')


def set_twitch_subscription(sub_type, user_info, token_info, say):
    logger.info(f'----- START set {sub_type} -----')
    logger.info(f'----- POST twitch api request {sub_type} event subscription -----')
    headers = twitch_api_header(token_info['access_token'])
    data = {
        'type': sub_type,
        'version': '1',
        'condition': {
            'broadcaster_user_id': user_info['data'][0]['id']
        },
        'transport': {
            'method': 'webhook',
            'callback': os.environ.get('URL'),
            'secret': 'aaaaaaaaaa'
        }
    }
    response = requests.post(
        f'{TWITCH_API_URL}/helix/eventsub/subscriptions',
        headers=headers, data=json.dumps(data)
    )
    logger.info(f'response={response.text}')

    logger.info('----- slack send chat message -----')
    payload = {
        'text': f'{user_info["data"][0]["display_name"]}さんの{sub_type}のevent subscriptionを要求しました。',
        'username': 'Twitch',
        'icon_emoji': ':twitch:',
    }
    logger.info(f'payload={payload}')
    say(payload)
    logger.info(f'----- END set {sub_type} -----')


@ flask_app.route('/twitch/token/validate', methods=['POST'])
def validate():
    get_trace_header(request)

    logger.info('===== START check access token =====')
    logger.info(f'request={request.get_data()}')

    try:
        validate_twitch_access_token()
    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END check access token =====')
        return 'OK', 200


def validate_twitch_access_token():
    logger.info('===== START validate twitch access token =====')
    twitch_oauth_token = get_firestore_twitch_token()
    twitch_oauth_access_token = twitch_oauth_token[0]
    twitch_oauth_refresh_token = twitch_oauth_token[1]

    logger.info('----- GET twitch api validate access token -----')
    headers = {
        'Authorization': f'Bearer {twitch_oauth_access_token}'
    }
    response = requests.get('https://id.twitch.tv/oauth2/validate', headers=headers)
    logger.info(f'response={response.text}')

    if response.status_code == 401:
        logger.info('----- POST twitch api refresh access token -----')
        response = requests.post(
            f'https://id.twitch.tv/oauth2/token?client_id={TWITCH_CLIENT_ID}&client_secret={TWITCH_CLIENT_SECRET}'
            f'&grant_type=refresh_token&refresh_token={twitch_oauth_refresh_token}',
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ).json()
        logger.info(f'response={response}')

        logger.info('----- update firestore twitch token -----')
        token = {
            'oauth_access_token': response['access_token'],
            'oauth_refresh_token': response['refresh_token']
        }
        firestore_client.collection('secretary_bot_v2').document('twitch').set(token)

    logger.info('===== END validate twitch access token =====')


@flask_app.route('/twitch/eventsub', methods=['POST'])
def event_subscription_handler():
    get_trace_header(request)

    logger.info('===== START event subscription handler =====')
    request_json = request.get_json()
    logger.info(f'request={request_json}')

    try:
        twitch_subscription_type = request_json["subscription"]["type"]
        logger.info(f'subscription_type={twitch_subscription_type}')

        validate_twitch_access_token()
        twitch_oauth_access_token = get_firestore_twitch_token()[0]

        logger.info('----- check message type notification -----')
        massage_type = 'Twitch-Eventsub-Message-Type'
        massage_type_notification = 'notification'
        massage_type_verification = 'webhook_callback_verification'

        twitch_broadcaster_user_id = request_json["event"]["broadcaster_user_id"]
        user_info = get_twitch_user_info(twitch_oauth_access_token, user_id=twitch_broadcaster_user_id)

        if massage_type_notification == request.headers[massage_type]:
            logger.info(f'message_type={massage_type_notification}')

            twitch_broadcaster_user_login = request_json['event']['broadcaster_user_login']
            if twitch_subscription_type == 'channel.update':
                logger.info('----- get firestore twitch streaming -----')
                now_streaming = firestore_client.collection('secretary_bot_v2').document(
                    'twitch_streaming').get().to_dict()[twitch_broadcaster_user_login]

                if now_streaming is False:
                    logger.info('===== SKIP event subscription handler =====')
                    return 'event subscription success!', 204

            logger.info('----- get firestore twitch eventsub id -----')
            doc_ref_event = firestore_client.collection('secretary_bot_v2').document('twitch_eventsub')
            converted_twitch_subscription_type = request_json['subscription']['type'].replace('.', '_')
            twitch_subscription_id = request_json['subscription']['id']
            if doc_ref_event.get().to_dict()[converted_twitch_subscription_type] == twitch_subscription_id:
                logger.info('===== SKIP event subscription handler =====')
                return 'event subscription success!', 204

            logger.info('----- update firestore twitch eventsub id -----')
            subscription_id = {
                converted_twitch_subscription_type: twitch_subscription_id,
            }
            firestore_client.collection('secretary_bot_v2').document('twitch_eventsub').update(subscription_id)

            logger.info('----- GET twitch api get channel info -----')
            headers = twitch_api_header(twitch_oauth_access_token)
            channel_info = requests.get(
                f'{TWITCH_API_URL}/helix/channels?broadcaster_id={twitch_broadcaster_user_id}',
                headers=headers
            ).json()
            logger.info(f'response={channel_info}')

            color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])
            twitch_broadcaster_user_name = request_json['event']['broadcaster_user_name']
            twitch_channel_title = channel_info['data'][0]['title']
            twitch_game_name = channel_info['data'][0]['game_name']
            twitch_stream_title = channel_info['data'][0]['title']
            twitch_profile_image_url = user_info['data'][0]['profile_image_url']
            twitch_user_login = user_info['data'][0]['login']

            if request_json['subscription']['type'] == 'stream.online':
                logger.info('----- update firestore twitch streaming status -----')
                firestore_client.collection('secretary_bot_v2').document(
                    'twitch_streaming').update({twitch_user_login: True})

                started_at = (
                    datetime.strptime(request_json['event']['started_at'], '%Y-%m-%dT%H:%M:%SZ') + timedelta(hours=9)
                ).strftime('%m月%d日 %H時%M分')

                attachment = [{
                    'color': color,
                    'blocks': [
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'*{twitch_broadcaster_user_name}*'
                            }
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'<https://www.twitch.tv/{twitch_broadcaster_user_login}|{twitch_channel_title}>'
                            }
                        },
                        {
                            'type': 'section',
                            'fields': [
                                {
                                    'type': 'mrkdwn',
                                    'text': '*Playing*'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': '*Started at*'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': twitch_game_name
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': started_at
                                }
                            ],
                            'accessory': {
                                'type': 'image',
                                'image_url': twitch_profile_image_url,
                                'alt_text': twitch_broadcaster_user_name
                            }
                        }
                    ]
                }]
            elif request_json['subscription']['type'] == 'channel.update':
                updated_at = (
                    datetime.now() + timedelta(hours=9)
                ).strftime('%m月%d日 %H時%M分')

                attachment = [{
                    'color': color,
                    'blocks': [
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'*{twitch_broadcaster_user_name}*'
                            }
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'<https://www.twitch.tv/{twitch_broadcaster_user_login}|{twitch_channel_title}>'
                            }
                        },
                        {
                            'type': 'section',
                            'fields': [
                                {
                                    'type': 'mrkdwn',
                                    'text': '*Playing*'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': '*Updated at*'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': twitch_game_name
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': updated_at
                                }
                            ],
                            'accessory': {
                                'type': 'image',
                                'image_url': twitch_profile_image_url,
                                'alt_text': twitch_broadcaster_user_name
                            }
                        }
                    ]
                }]
            elif request_json['subscription']['type'] == 'stream.offline':
                logger.info('----- update firestore twitch streaming status -----')
                firestore_client.collection('secretary_bot_v2').document(
                    'twitch_streaming').update({twitch_user_login: False})
                return 'event subscription success!', 204

            post_slack_message(
                TWITCH_SLACK_CHANNEL_ID,
                text=f'{twitch_broadcaster_user_name}さんがライブ配信中です！ {twitch_game_name} : {twitch_stream_title}',
                attachments=json.dumps(attachment),
                username='Twitch',
                icon_emoji=':twitch:'
            )

            return 'event subscription success!', 204

        elif massage_type_verification == request.headers[massage_type]:
            logger.info(f'message_type={massage_type_verification}')

            color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])
            twitch_user_login = user_info['data'][0]['login']
            twitch_profile_image_url = user_info['data'][0]['profile_image_url']
            twitch_user_display_name = user_info['data'][0]['display_name']

            attachment = [{
                'color': color,
                'blocks': [
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f'<https://www.twitch.tv/{twitch_user_login}|Success {twitch_subscription_type} {twitch_user_display_name} event subscription !>'
                        },
                        'accessory': {
                            'type': 'image',
                            'image_url': twitch_profile_image_url,
                            'alt_text': twitch_user_display_name
                        }
                    },
                ]
            }]

            post_slack_message(
                TWITCH_SLACK_CHANNEL_ID,
                text='Event Subscription',
                attachments=json.dumps(attachment),
                username='Twitch',
                icon_emoji=':twitch:'
            )

            return request_json['challenge'], 200

    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END event subscription handler =====')


# =========================================================
@bolt_app.message('hello')
def message_hello(message, say):
    logger.info(f'request={message}')
    say(f'Hey there <@{message["user"]}>!')


@bolt_app.event("app_mention")
def response_message(event, ack, say):
    ack()
    logger.info('===== START text-davinci-003 mention response =====')
    logger.info(f'request={event}')

    try:
        logger.info('----- get openai chat response text')
        openai.api_key = secret_client.access_secret_version(
            request={'name': 'projects/831232013080/secrets/OPENAI_API_KEY/versions/latest'}
        ).payload.data.decode('UTF-8')

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
        logger.info(f'response={response}')
        texts = ''.join([choice['text'] for choice in response.choices])
        texts = texts.strip("\n")

        logger.info('----- update firestore openai chat history -----')
        firestore_client.collection('secretary_bot_v2').document('openai').update({'history': prompt + texts + '\n\n'})

        blocks = [
            {
                "type": "section",
                "text": {
                        "type": "mrkdwn",
                        "text": fr'<@{event["user"]}> {texts}'
                }
            }
        ]

        logger.info('----- slack send chat message -----')
        payload = {
            'blocks': blocks,
            'icon_emoji': ':secretary:',
        }
        logger.info(f'payload={payload}')
        say(payload)

    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END text-davinci-003 mention response =====')


@ flask_app.route('/gcp/notify_gcp_cost', methods=['POST'])
def notify_gcp_cost():
    get_trace_header(request)

    logger.info('===== START notify gcp cost =====')
    logger.info(f'request={request.get_data()}')

    try:
        logger.info('----- get bigquery gcp cost top 3 -----')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

        top_query = f"""
            SELECT service.description as service, sku.description as sku, ROUND(SUM(cost), 2) AS cost
            FROM `{TABLE_ID}`
            WHERE project.id = 'slackbot-288310' AND FORMAT_DATE('%Y-%m-%d',usage_start_time) = '{yesterday}'
            GROUP BY service, sku
            HAVING cost != 0
            ORDER BY cost desc
            LIMIT 3
        """
        logger.info(f'top_query={top_query}')

        query_job = bq_client.query(top_query)
        top_query_result = []
        for row in query_job:
            top_query_result.append({'service': row['service'], 'sku': row['sku'], 'cost': row['cost']})
        logger.info(f'top_query_result={top_query_result}')

        logger.info('----- get bigquery gcp cost total -----')
        total_query = f"""
            SELECT SUM(cost) AS cost
            FROM `{TABLE_ID}`
            WHERE project.id = 'slackbot-288310' AND FORMAT_DATE('%Y-%m-%d',usage_start_time) = '{yesterday}'
        """
        logger.info(f'top_query={total_query}')

        query_job = bq_client.query(total_query)
        total_query_result = None
        for row in query_job:
            total_query_result = row['cost']
        logger.info(f'total_query_result={total_query_result}')

        color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])

        attachment = [{
            'color': color,
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f'*{yesterday} Total Cost*\n{total_query_result} JPY'
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

        post_slack_message(
            GCP_NOTICE_SLACK_CHANNEL_ID,
            text='Notify Today GCP Cost',
            attachments=json.dumps(attachment),
            username='Notify GCP Cost',
            icon_emoji=':gcp:'
        )

        return 'notify gcp cost success!', 204

    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END notify gcp cost =====')


@ bolt_app.command('/openai')
def openai(ack, say, command):
    ack()
    logger.info('===== START slash command /openai =====')
    logger.info(f'request={command}')

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


@ bolt_app.command('/test')
def test(ack, say, command):
    ack()
    logger.info(f'request={command}')
    say('OK!')


@ bolt_app.event("message")  # ロギング
def handle_message_events(body, logger):
    logger.info(body)


@ flask_app.route('/', methods=['POST'])
def index():
    get_trace_header(request)
    logger.info(f'request={request.get_data()}')
    return 'Flask Test'


@ flask_app.route('/slack/events', methods=['POST'])
def slack_events():
    get_trace_header(request)
    return handler.handle(request)


if __name__ == '__main__':
    flask_app.run(port=int(os.environ.get('PORT', 3000)))
