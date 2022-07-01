import inspect
import json
import os
import pprint
import re
import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from dotenv import load_dotenv
from flask import Flask, request
from pathlib import Path
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_bolt.oauth.oauth_settings import OAuthSettings
from slack_bolt.oauth.callback_options import CallbackOptions, SuccessArgs, FailureArgs
from slack_bolt.response import BoltResponse

########################################
#               TOKENS                 #
########################################

load_dotenv()

GITLAB_TOKEN = os.getenv('GITLAB_TOKEN')
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')
SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')
KEY_VAULT_NAME = os.getenv('KEY_VAULT_NAME')

########################################
#               GITLAB                 #
########################################

headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}

########################################
#           AZURE KEY VAULT            #
########################################

kv_url = f'https://{KEY_VAULT_NAME}.vault.azure.net'
kv_credential = DefaultAzureCredential()
kv_client = SecretClient(vault_url=kv_url, credential=kv_credential)

########################################
#                USERS                 #
########################################

"""
def load_users():
    with open("users/users.json", 'r') as r:
        return json.load(r)
"""

def load_users():
    usernames = kv_client.get_secret("usernames")

    users = {}
    for user in json.loads(usernames.value)['usernames']:
        users[user] = json.loads(kv_client.get_secret(user).values)

users = load_users()

slack_ids = {
    "U03K8739CF8": "nuno.venturinha",
    "U03KPHMT3K7": "paulo.jesus"
}

########################################
#            PROJECT IDS               #
########################################

project_ids = {
    "ad-blueprints": 18074,
    "ad-tools": 20129,
    "blueprints": 3670,
    "jte-library": 18571,
    "provision": 18890,
    "provision-scripts": 21415,
    "saltstack": 3874,
    "update-blueprints": 14837
}

########################################
#               TOOLS                  #
########################################

def find_by_key(data, target):
    for k, v in data.items():
        if k == target:
            return v
        elif isinstance(v, dict):
            return find_by_key(v, target)
        elif isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    return find_by_key(i, target)

def get_mr_url(url):
    prt = url.partition("/merge_requests/")
    project_name = prt[0].rsplit(sep="/", maxsplit=1)[1]
    mergerequest_id = re.sub("\D", "", url)
    project_id = project_ids[project_name]
    url_base = "https://gitlab.fftech.info/api/v4/projects/"
    
    return f'{url_base}{project_id}/merge_requests/{mergerequest_id}'

def add_user(users, user_name, gitlab_token=None, slack_id=None, slack_token=None):

    users[user_name] = {
        "gitlab_token": gitlab_token,
        "slack_id": slack_id,
        "slack_token": slack_token
    }

def block_create(title, author_url, author_name, project_id, state, upvotes, web_url):
    frame = inspect.currentframe()
    try:
        args, _, _, values = inspect.getargvalues(frame)
        txt = Path("templates/block_mr.json").read_text()
        for arg in args:
            txt = re.sub(f'\${arg}\$', f'{values[arg]}', txt)
    finally:
        del frame
        return txt

########################################
#               CALLBACK               #
########################################

def success(args: SuccessArgs) -> BoltResponse:
    assert args.request is not None
    user_id = args.installation.user_id
    user_token = args.installation.user_token
    user_name = app.client.users_info(token=SLACK_BOT_TOKEN, user=user_id)['user']['name']
    user = {
        'user_name': user_name,
        'user_id': user_id,
        'user_token': user_token
    }
    with open(f'users/{user_id}', 'w') as outfile:
        json.dump(user, outfile, indent=4)
    return BoltResponse(
        status=200,
        body="User token creation sucess :)"
    )

def failure(args: FailureArgs) -> BoltResponse:
    assert args.request is not None
    assert args.reason is not None
    return BoltResponse(
        status=args.suggested_status_code,
        body="User token creation fail :("
    )


########################################
#               BOLT                   #
########################################

oauth_settings = OAuthSettings(
    client_id=SLACK_CLIENT_ID,
    client_secret=SLACK_CLIENT_SECRET,
    user_scopes=["reactions:write"],
    #redirect_uri="https://salty-buckets-begin-89-115-249-50.loca.lt/slack/oauth_redirect",
    callback_options=CallbackOptions(success=success, failure=failure)
)

app = App(
    signing_secret=SLACK_SIGNING_SECRET,
    oauth_settings=oauth_settings
)

########################################
#               EVENTS                 #
########################################

@app.event("reaction_added")
def handle_reaction_added(context, event, body, request, req, payload):
    if event['reaction'] == '+1':
        result = app.client.conversations_history(token=SLACK_BOT_TOKEN, channel=event['item']['channel'],
                                                    inclusive=True, oldest=event['item']['ts'], limit=1)
        url_given = find_by_key(result['messages'][0], "url")

        mr = requests.post(f'{get_mr_url(url_given)}/award_emoji?name=thumbsup', headers=headers).json()
    pprint.pprint(mr)


@app.event("reaction_removed")
def handle_reaction_removed(event):
    if event['reaction'] == '+1':
        result = app.client.conversations_history(token=SLACK_BOT_TOKEN, channel=event['item']['channel'],
                                                    inclusive=True, oldest=event['item']['ts'], limit=1)
        url_given = find_by_key(result['messages'][0], "url")

        emojis = requests.get(f'{get_mr_url(url_given)}/award_emoji', headers=headers).json()
        for emoji in emojis:
            if emoji['user']['username'] == slack_ids[event['user']]:
                award_id = emoji['id']

        requests.delete(f'{get_mr_url(url_given)}/award_emoji/{award_id}', headers=headers)


@app.message("merge_requests")
def handle_mr_added(message, say, event):

    url_given = find_by_key(message, "url")

    mr = requests.get(get_mr_url(url_given), headers=headers).json()

    blocks = block_create(title=mr['title'], author_url=mr['author']['web_url'], author_name=mr['author']['name'], 
                            project_id=mr['project_id'], state=mr['state'], upvotes=mr['upvotes'], web_url=mr['web_url'])

    say(token=SLACK_BOT_TOKEN, text="", blocks=blocks)

########################################
#              / COMMANDS              #
########################################

@app.command("/openmr")
def message_history(ack, say, context, event):
    ack()
    ok = app.client.conversations_history(token=SLACK_BOT_TOKEN, channel=context['channel_id'])

    message_list = set()
    for message in ok['messages']:
        message_list.add(find_by_key(message, "url"))
    message_list.remove(None)

    pprint.pprint(message_list)
"""
    blocks = []
    blocks.append(
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Open Merge Requests"
            }
        }
    )
    for message in message_list:
        headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
        mr = requests.get(get_mr_url(message), headers=headers).json()
        if mr['state'] == "opened":
            blocks.extend((
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{mr['title']}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Created by:*\n<{mr['author']['web_url']}|{mr['author']['name']}>"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Project:*\n{[key for key, value in project_ids.items() if value == mr['project_id']][0]}"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*State:*\n{mr['state']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Thumbs Up:*\n{mr['upvotes']} :thumbsup:"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{mr['web_url']}|View merge request>"
                }
            },
            {
                "type": "divider"
            }
            ))

    say(token=SLACK_BOT_TOKEN, blocks=blocks)
"""

########################################
#               FLASK                  #
########################################
flask_app = Flask(__name__)
handler = SlackRequestHandler(app)

@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)

@flask_app.route("/slack/install", methods=["GET"])
def slack_install():
    return handler.handle(request)

@flask_app.route("/slack/oauth_redirect", methods=["GET"])
def slack_oauth_redirect():
    return handler.handle(request)
