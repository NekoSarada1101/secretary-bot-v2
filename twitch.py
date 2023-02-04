from flask import Blueprint
from app import *

bp = Blueprint('twitch', __name__)


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
    get_trace_header(request)

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
    get_trace_header(request)

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
                updated_at = (datetime.now() + timedelta(hours=9)).strftime('%m月%d日 %H時%M分')

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
                                    'text': 'Updated at'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': updated_at
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