import streamlit as st
import os
import asyncio
from httpx_oauth.clients.google import GoogleOAuth2
from oauthlib.oauth2 import WebApplicationClient

if __name__ == '__main__':
    client_id = st.secrets["GOOGLE_CLIENT_ID"]
    client_secret = st.secrets["GOOGLE_CLIENT_SECRET"]
    redirect_uri = st.secrets["REDIRECT_URI"]

    client = GoogleOAuth2(client_id, client_secret)
    oauth_client = WebApplicationClient(client_id)
    authorization_url, _ = oauth_client.prepare_request_uri(
        "https://accounts.google.com/o/oauth2/auth",
        redirect_uri=redirect_uri,
        scope=["openid", "email", "profile"],
    )

    if "token" not in st.session_state:
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
                    st.session_state.token = token
                    user_id, user_email = asyncio.run(
                        get_email(client=client, token=token['access_token'])
                    )
                    st.session_state.user_id = user_id
                    st.session_state.user_email = user_email
                    main(user_id=st.session_state.user_id, user_email=st.session_state.user_email)
    else:
        main(user_id=st.session_state.user_id, user_email=st.session_state.user_email)