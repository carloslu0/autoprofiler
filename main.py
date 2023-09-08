import streamlit as st
import os
import asyncio
from session_state import get
from httpx_oauth.clients.google import GoogleOAuth2
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

async def write_authorization_url(client, redirect_uri):
    authorization_url = await client.get_authorization_url(
        redirect_uri,
        scope=["profile", "email", "https://www.googleapis.com/auth/gmail.readonly"],
        extras_params={"access_type": "offline"},
    )
    return authorization_url

async def write_access_token(client, redirect_uri, code):
    token = await client.get_access_token(code, redirect_uri)
    return token

async def get_email(client, token):
    user_id, user_email = await client.get_id_email(token)
    return user_id, user_email

def get_gmail_service():
    creds = Credentials.from_authorized_user_info(info=session_state.token)
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_emails_with_label(service, label):
    try:
        results = service.users().messages().list(userId='me', labelIds=[label]).execute()
        messages = results.get('messages', [])
        return messages
    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

def main(user_id, user_email):
    st.write(f"You're logged in as {user_email}")

    label = st.text_input("Please provide the label you want to use for filtering Gmail emails:")
    if label:
        service = get_gmail_service()
        emails = get_emails_with_label(service, label)
        if emails:
            st.write(f"Found {len(emails)} emails with label '{label}':")
            for email in emails:
                st.write(f"Email ID: {email['id']}")
        else:
            st.write(f"No emails found with label '{label}'.")

if __name__ == '__main__':
    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    client_secret = st.secrets["GOOGLE_CLIENT_SECRET"]
    redirect_uri = st.secrets["REDIRECT_URI"]

    client = GoogleOAuth2(client_id, client_secret)
    authorization_url = asyncio.run(
        write_authorization_url(client=client, redirect_uri=redirect_uri)
    )

    session_state = get(token=None)
    if session_state.token is None:
        try:
            code = st.experimental_get_query_params()['code']
        except:
            st.write(f'''<h1>
                Please login using this <a target="_self"
                href="{authorization_url}">url</a></h1>''',
                     unsafe_allow_html=True)
        else:
            try:
                token = asyncio.run(
                    write_access_token(client=client, redirect_uri=redirect_uri, code=code))
            except:
                st.write(f'''<h1>
                    This account is not allowed or page was refreshed.
                    Please try again: <a target="_self"
                    href="{authorization_url}">url</a></h1>''',
                         unsafe_allow_html=True)
            else:
                if token.is_expired():
                    st.write(f'''<h1>
                    Login session has ended,
                    please <a target="_self" href="{authorization_url}">
                    login</a> again.</h1>
                    ''')
                else:
                    session_state.token = token
                    user_id, user_email = asyncio.run(
                        get_email(client=client, token=token['access_token'])
                    )
                    session_state.user_id = user_id
                    session_state.user_email = user_email
                    main(user_id=session_state.user_id, user_email=session_state.user_email)
    else:
        main(user_id=session_state.user_id, user_email=session_state.user_email)