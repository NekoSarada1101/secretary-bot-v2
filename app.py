import os
import sys
import requests
import logging
import json
import traceback
from slack_bolt import App
from google.cloud import firestore, secretmanager

secret_client = secretmanager.SecretManagerServiceClient()
firestore_client = firestore.Client()


SLACK_BOT_TOKEN = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_BOT_TOKEN/versions/latest'}).payload.data.decode('UTF-8')

SLACK_SIGNING_SECRET = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_SLACK_SIGNING_SECRET/versions/latest'}).payload.data.decode('UTF-8')

TWITCH_CLIENT_ID = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_ID/versions/latest'}).payload.data.decode('UTF-8')

TWITCH_CLIENT_SECRET = secret_client.access_secret_version(request={'name': 'projects/831232013080/secrets/SECRETARY_BOT_V2_TWITCH_CLIENT_SECRET/versions/latest'}).payload.data.decode('UTF-8')

USER_ID = os.environ.get('USER_ID')

app = App(token=SLACK_BOT_TOKEN,
          signing_secret=SLACK_SIGNING_SECRET)


class JsonFormatter(logging.Formatter):
    def format(self, log):
        return json.dumps({
            'level': log.levelname,
            'message': log.getMessage(),
            'timestamp': self.formatTime(log, self.datefmt),
            'traceback': traceback.format_exc() if log.exc_info else []
        })

formatter = JsonFormatter(datefmt="%Y-%m-%d %H:%M:%S")
stream = logging.StreamHandler(stream=sys.stdout)
stream.setFormatter(formatter)

logger = logging.getLogger('sample')
logger.setLevel(logging.INFO)
logger.addHandler(stream)


@app.message("hello")
def message_hello(message, say):
    logger.info('request={}'.format(message))
    say(f"Hey there <@{message['user']}>!")


@app.command("/twitch")
def twitch(ack, say, command):
    logger.info('----- start slash command /twitch -----')
    logger.info('request={}'.format(command))
    ack()

    logger.info('----- get firestore -----')
    doc_ref = firestore_client.collection('secretary_bot_v2').document('twitch')

    logger.info('----- post twitch api -----')
    headers = {
        'Authorization': 'Bearer {}'.format(doc_ref.get().to_dict()['oauth_access_token']),
        'Client-Id': TWITCH_CLIENT_ID
    }
    response = requests.get('https://api.twitch.tv/helix/streams/followed?user_id={}'.format(USER_ID), headers=headers)
    logger.info('response={}'.format(response.text))

    if response.status_code == 401:
        logger.info('----- refresh twitch access token -----')
        response = requests.post('https://id.twitch.tv/oauth2/token?client_id={}&client_secret={}&grant_type=refresh_token&refresh_token={}'.format(
            TWITCH_CLIENT_ID,
            TWITCH_CLIENT_SECRET,
            doc_ref.get().to_dict()['oauth_refresh_token']),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        logger.info('response={}'.format(response.text))

        response_json = response.json()
        token = {
            'oauth_access_token': response_json['access_token'],
            'oauth_refresh_token': response_json['refresh_token']
        }
        firestore_client.collection('secretary_bot_v2').document('twitch').set(token)

        logger.info('----- post twitch api -----')
        headers = {
            'Authorization': 'Bearer {}'.format(doc_ref.get().to_dict()['oauth_access_token']),
            'Client-Id': TWITCH_CLIENT_ID
        }
        response = requests.get('https://api.twitch.tv/helix/streams/followed?user_id={}'.format(USER_ID), headers=headers)
        logger.info('response={}'.format(response.text))

    say(response.text)
    logger.info('----- end slash command /twitch -----')


if __name__ == "__main__":
    app.start(port=int(os.environ.get("PORT", 3000)))
