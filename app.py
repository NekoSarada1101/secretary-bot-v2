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

if __name__ == "__main__":
    app.start(port=int(os.environ.get("PORT", 3000)))
