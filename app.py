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
from google.cloud import firestore, secretmanager


# constant ============================================
secret_client = secretmanager.SecretManagerServiceClient()
firestore_client = firestore.Client()

SLACK_BOT_TOKEN = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_BOT_TOKEN/versions/latest'}).payload.data.decode('UTF-8')
SLACK_SIGNING_SECRET = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_SIGNING_SECRET/versions/latest'}).payload.data.decode('UTF-8')
TWITCH_CLIENT_ID = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_ID/versions/latest'}).payload.data.decode('UTF-8')
TWITCH_CLIENT_SECRET = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_SECRET/versions/latest'}).payload.data.decode('UTF-8')
USER_ID = os.environ.get('USER_ID')
TWITCH_SLACK_CHANNEL_ID = os.environ.get('TWITCH_SLACK_CHANNEL_ID')

flask_app = Flask(__name__)
bolt_app = App(token=SLACK_BOT_TOKEN,
               signing_secret=SLACK_SIGNING_SECRET)
handler = SlackRequestHandler(bolt_app)


# logger ===============================================
class JsonFormatter(logging.Formatter):
    def format(self, log):
        return json.dumps({
            'level': log.levelname,
            'message': log.getMessage(),
        })


formatter = JsonFormatter()
stream = logging.StreamHandler(stream=sys.stdout)
stream.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(stream)


# functions ==========================================
@bolt_app.command('/twitch')
def twitch(ack, say, command):
    ack()
    logger.info('===== START slash command /twitch =====')
    logger.info('request={}'.format(command))

    try:
        validate_twitch_access_token()

        logger.info('----- get firestore twitch token -----')
        doc_ref = firestore_client.collection('secretary_bot_v2').document('twitch')

        values = command['text'].split(' ')

        if values[0] == 'now':
            logger.info('===== START get now on streaming list =====')
            logger.info('----- GET twitch api get follow list -----')
            headers = {
                'Authorization': 'Bearer {}'.format(doc_ref.get().to_dict()['oauth_access_token']),
                'Client-Id': TWITCH_CLIENT_ID
            }
            response = requests.get('https://api.twitch.tv/helix/streams/followed?user_id={}'.format(USER_ID), headers=headers)
            logger.info('response={}'.format(response.text))

            response_json = response.json()
            attachments = []

            for res in response_json['data']:
                logger.info('----- GET twitch api get user info -----')
                user_info = requests.get('https://api.twitch.tv/helix/users?id={}'.format(res['user_id']), headers=headers).json()
                logger.info('response={}'.format(user_info))

                color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])
                started_at = datetime.strptime(res['started_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%m月%d日 %H時%M分')

                attachment = {
                    'color': color,
                    'blocks': [
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': '*{}*'.format(res['user_name'])
                            }
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': '<https://www.twitch.tv/{}|{}>'.format(res['user_login'], res['title'])
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
            logger.info('payload={}'.format(payload))
            say(payload)

        elif values[0] == 'sub':
            logger.info('===== START set event subscription =====')
            logger.info('----- START set stream.online -----')
            logger.info('----- GET twitch api get user info -----')
            headers = {
                'Authorization': 'Bearer {}'.format(doc_ref.get().to_dict()['oauth_access_token']),
                'Client-Id': TWITCH_CLIENT_ID
            }
            user_info = requests.get('https://api.twitch.tv/helix/users?login={}'.format(values[1]), headers=headers).json()
            logger.info('response={}'.format(user_info))

            logger.info('----- POST twitch api get app access token -----')
            token_info = requests.post('https://id.twitch.tv/oauth2/token?client_id={}&client_secret={}&grant_type=client_credentials'.format(TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET))
            logger.info('response={}'.format(token_info.text))

            logger.info('----- POST twitch api request stream.online event subscription -----')
            headers = {
                'Authorization': 'Bearer {}'.format(token_info.json()['access_token']),
                'Client-Id': TWITCH_CLIENT_ID,
                'Content-Type': 'application/json',
            }
            data = {
                'type': 'stream.online',
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
            response = requests.post('https://api.twitch.tv/helix/eventsub/subscriptions', headers=headers, data=json.dumps(data))
            logger.info('response={}'.format(response.text))

            logger.info('----- slack send chat message -----')
            payload = {
                'text': '{}さんのstream.onlineのevent subscriptionを要求しました。'.format(user_info['data'][0]['display_name']),
                'username': 'Twitch',
                'icon_emoji': ':twitch:',
            }
            logger.info('payload={}'.format(payload))
            say(payload)
            logger.info('----- END set stream.online -----')

            logger.info('----- START set channel.update -----')
            logger.info('----- POST twitch api request channel.update event subscription -----')
            headers = {
                'Authorization': 'Bearer {}'.format(token_info.json()['access_token']),
                'Client-Id': TWITCH_CLIENT_ID,
                'Content-Type': 'application/json',
            }
            data = {
                'type': 'channel.update',
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
            response = requests.post('https://api.twitch.tv/helix/eventsub/subscriptions', headers=headers, data=json.dumps(data))
            logger.info('response={}'.format(response.text))

            logger.info('----- slack send chat message -----')
            payload = {
                'text': '{}さんのchannel.updateのevent subscriptionを要求しました。'.format(user_info['data'][0]['display_name']),
                'username': 'Twitch',
                'icon_emoji': ':twitch:',
            }
            logger.info('payload={}'.format(payload))
            say(payload)
            logger.info('----- END set channel.update -----')

            logger.info('----- START set stream.offline -----')
            logger.info('----- POST twitch api request stream.offline event subscription -----')
            headers = {
                'Authorization': 'Bearer {}'.format(token_info.json()['access_token']),
                'Client-Id': TWITCH_CLIENT_ID,
                'Content-Type': 'application/json',
            }
            data = {
                'type': 'stream.offline',
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
            response = requests.post('https://api.twitch.tv/helix/eventsub/subscriptions', headers=headers, data=json.dumps(data))
            logger.info('response={}'.format(response.text))

            logger.info('----- slack send chat message -----')
            payload = {
                'text': '{}さんのstream.offlineのevent subscriptionを要求しました。'.format(user_info['data'][0]['display_name']),
                'username': 'Twitch',
                'icon_emoji': ':twitch:',
            }
            logger.info('payload={}'.format(payload))
            say(payload)
            logger.info('----- END set stream.offline -----')

            logger.info('----- update firestore twitch streaming status -----')
            firestore_client.collection('secretary_bot_v2').document('twitch_streaming').update({user_info['data'][0]['login']: False})

            logger.info('===== END set event subscription =====')

    except Exception as e:
        logger.error(e)
        say('エラーが発生しました。ログを確認してください。')
    finally:
        logger.info('===== END slash command /twitch =====')


@ flask_app.route('/twitch/token/validate', methods=['POST'])
def validate():
    logger.info('===== START check access token =====')
    logger.info('request={}'.format(request.get_data()))
    try:
        validate_twitch_access_token()
    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END check access token =====')
        return 'OK', 200


def validate_twitch_access_token():
    logger.info('===== START validate twitch access token =====')
    logger.info('----- get firestore twitch token -----')
    doc_ref = firestore_client.collection('secretary_bot_v2').document('twitch')

    logger.info('----- GET twitch api validate access token -----')
    headers = {
        'Authorization': 'Bearer {}'.format(doc_ref.get().to_dict()['oauth_access_token'])
    }
    response = requests.get('https://id.twitch.tv/oauth2/validate', headers=headers)
    logger.info('response={}'.format(response.text))

    if response.status_code == 401:
        logger.info('----- POST twitch api refresh access token -----')
        response = requests.post('https://id.twitch.tv/oauth2/token?client_id={}&client_secret={}&grant_type=refresh_token&refresh_token={}'.format(
            TWITCH_CLIENT_ID,
            TWITCH_CLIENT_SECRET,
            doc_ref.get().to_dict()['oauth_refresh_token']),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        logger.info('response={}'.format(response.text))

        logger.info('----- update firestore twitch token -----')
        response_json = response.json()
        token = {
            'oauth_access_token': response_json['access_token'],
            'oauth_refresh_token': response_json['refresh_token']
        }
        firestore_client.collection('secretary_bot_v2').document('twitch').set(token)

    logger.info('===== END validate twitch access token =====')


@flask_app.route('/twitch/eventsub', methods=['POST'])
def event_subscription_handler():
    logger.info('===== START event subscription handler =====')
    request_json = request.get_json()
    logger.info('request={}'.format(request_json))
    logger.info('subscription_type={}'.format(request_json['subscription']['type']))

    try:
        validate_twitch_access_token()

        logger.info('----- get firestore twitch token -----')
        doc_ref = firestore_client.collection('secretary_bot_v2').document('twitch')

        logger.info('----- check message type notification -----')
        massage_type = 'Twitch-Eventsub-Message-Type'
        massage_type_notification = 'notification'
        massage_type_verification = 'webhook_callback_verification'

        if massage_type_notification == request.headers[massage_type]:
            logger.info('message_type={}'.format(massage_type_notification))

            if request_json['subscription']['type'] == 'channel.update':
                logger.info('----- get firestore twitch streaming -----')
                now_streaming = firestore_client.collection('secretary_bot_v2').document('twitch_streaming').get().to_dict()[request_json['event']['broadcaster_user_login']]

                if now_streaming == False:
                    logger.info('===== SKIP event subscription handler =====')
                    return 'event subscription success!', 204

            logger.info('----- get firestore twitch eventsub id -----')
            doc_ref_event = firestore_client.collection('secretary_bot_v2').document('twitch_eventsub')
            subscription_type = request_json['subscription']['type'].replace('.', '_')
            if doc_ref_event.get().to_dict()[subscription_type] == request_json['subscription']['id']:
                logger.info('===== SKIP event subscription handler =====')
                return 'event subscription success!', 204

            logger.info('----- update firestore twitch eventsub id -----')
            subscription_id = {
                subscription_type: request_json['subscription']['id'],
            }
            firestore_client.collection('secretary_bot_v2').document('twitch_eventsub').update(subscription_id)

            logger.info('----- GET twitch api get user info -----')
            headers = {
                'Authorization': 'Bearer {}'.format(doc_ref.get().to_dict()['oauth_access_token']),
                'Client-Id': TWITCH_CLIENT_ID
            }
            user_info = requests.get('https://api.twitch.tv/helix/users?id={}'.format(
                request_json['event']['broadcaster_user_id']),
                headers=headers
            ).json()
            logger.info('response={}'.format(user_info))

            logger.info('----- GET twitch api get channel info -----')
            channel_info = requests.get('https://api.twitch.tv/helix/channels?broadcaster_id={}'.format(
                request_json['event']['broadcaster_user_id']),
                headers=headers
            ).json()
            logger.info('response={}'.format(channel_info))

            color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])

            if request_json['subscription']['type'] == 'stream.online':
                logger.info('----- update firestore twitch streaming status -----')
                firestore_client.collection('secretary_bot_v2').document('twitch_streaming').update({user_info['data'][0]['login']: True})

                started_at = (datetime.strptime(request_json['event']['started_at'], '%Y-%m-%dT%H:%M:%SZ') + timedelta(hours=9)).strftime('%m月%d日 %H時%M分')

                attachment = [{
                    'color': color,
                    'blocks': [
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': '*{}*'.format(request_json['event']['broadcaster_user_name'])
                            }
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': '<https://www.twitch.tv/{}|{}>'.format(request_json['event']['broadcaster_user_login'], channel_info['data'][0]['title'])
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
                                    'text': channel_info['data'][0]['game_name']
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': started_at
                                }
                            ],
                            'accessory': {
                                'type': 'image',
                                'image_url': user_info['data'][0]['profile_image_url'],
                                'alt_text': request_json['event']['broadcaster_user_name']
                            }
                        }
                    ]
                }]
            elif request_json['subscription']['type'] == 'channel.update':
                attachment = [{
                    'color': color,
                    'blocks': [
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': '*{}*'.format(request_json['event']['broadcaster_user_name'])
                            }
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': '<https://www.twitch.tv/{}|{}>'.format(request_json['event']['broadcaster_user_login'], channel_info['data'][0]['title'])
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
                                    'text': '*Type*'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': channel_info['data'][0]['game_name']
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': 'channel.update'
                                }
                            ],
                            'accessory': {
                                'type': 'image',
                                'image_url': user_info['data'][0]['profile_image_url'],
                                'alt_text': request_json['event']['broadcaster_user_name']
                            }
                        }
                    ]
                }]
            elif request_json['subscription']['type'] == 'stream.offline':
                logger.info('----- update firestore twitch streaming status -----')
                firestore_client.collection('secretary_bot_v2').document('twitch_streaming').update({user_info['data'][0]['login']: False})
                return 'event subscription success!', 204

            logger.info('----- POST slack api send chat message -----')
            payload = {
                'token': SLACK_BOT_TOKEN,
                'channel': TWITCH_SLACK_CHANNEL_ID,
                'text': '{} now streaming {}'.format(request_json['event']['broadcaster_user_name'], channel_info['data'][0]['game_name']),
                'attachments': json.dumps(attachment),
                'username': 'Twitch',
                'icon_emoji': ':twitch:',
            }
            logger.info('payload={}'.format(payload))

            response = requests.post('https://slack.com/api/chat.postMessage', data=payload)
            logger.info('response={}'.format(response.text))

            return 'event subscription success!', 204

        elif massage_type_verification == request.headers[massage_type]:
            logger.info('message_type={}'.format(massage_type_verification))
            logger.info('request={}'.format(request.get_data()))

            logger.info('----- GET twitch api get user info -----')
            headers = {
                'Authorization': 'Bearer {}'.format(doc_ref.get().to_dict()['oauth_access_token']),
                'Client-Id': TWITCH_CLIENT_ID
            }
            user_info = requests.get('https://api.twitch.tv/helix/users?id={}'.format(
                request.get_json()['subscription']['condition']['broadcaster_user_id']),
                headers=headers
            ).json()
            logger.info('response={}'.format(user_info))

            logger.info('----- POST slack api send chat message -----')
            color = '#'+''.join([random.choice('0123456789ABCDEF') for j in range(6)])
            attachment = [{
                'color': color,
                'blocks': [
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': '<https://www.twitch.tv/{}|Success {} {} event subscription !>'.format(user_info['data'][0]['login'], request.get_json()['subscription']['type'], user_info['data'][0]['display_name'])
                        },
                        'accessory': {
                            'type': 'image',
                            'image_url': user_info['data'][0]['profile_image_url'],
                            'alt_text': user_info['data'][0]['display_name']
                        }
                    },
                ]
            }]

            payload = {
                'token': SLACK_BOT_TOKEN,
                'channel': TWITCH_SLACK_CHANNEL_ID,
                'text': 'Event Subscription',
                'attachments': json.dumps(attachment),
                'username': 'Twitch',
                'icon_emoji': ':twitch:',
            }
            logger.info('payload={}'.format(payload))

            response = requests.post('https://slack.com/api/chat.postMessage', data=payload)
            logger.info('response={}'.format(response.text))

            return request.get_json()['challenge'], 200

    except Exception as e:
        logger.error(e)
    finally:
        logger.info('===== END event subscription handler =====')


# =========================================================
@bolt_app.message('hello')
def message_hello(message, say):
    logger.info('request={}'.format(message))
    say(f'Hey there <@{message["user"]}>!')


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


@bolt_app.command('/openai')
def test(ack, say, command):
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


@bolt_app.command('/test')
def test(ack, say, command):
    ack()
    logger.info('request={}'.format(command))
    say('OK!')


@flask_app.route('/', methods=['POST'])
def index():
    logger.info('request={}'.format(request.get_data()))
    return 'Flask Test'


@flask_app.route('/slack/events', methods=['POST'])
def slack_events():
    return handler.handle(request)


if __name__ == '__main__':
    flask_app.run(port=int(os.environ.get('PORT', 3000)))
