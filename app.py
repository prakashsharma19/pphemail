import streamlit as st
import boto3
import pandas as pd
import datetime
import time
import requests
import json
import os
import sys
import subprocess
from datetime import datetime, timedelta
from io import StringIO
from google.cloud import storage
from google.oauth2 import service_account

# App Configuration
st.set_page_config(page_title="Email Marketing Suite", layout="wide")

# Initialize session state variables
def init_session_state():
    if 'ses_client' not in st.session_state:
        st.session_state.ses_client = None
    if 'firebase_storage' not in st.session_state:
        st.session_state.firebase_storage = None
    if 'firebase_initialized' not in st.session_state:
        st.session_state.firebase_initialized = False
    if 'selected_journal' not in st.session_state:
        st.session_state.selected_journal = None

init_session_state()

# Load configuration from secrets
@st.cache_data
def load_config():
    config = {
        'aws': {
            'access_key': st.secrets.get("aws.ACCESS_KEY_ID", ""),
            'secret_key': st.secrets.get("aws.SECRET_ACCESS_KEY", ""),
            'region': 'us-east-1'
        },
        'millionverifier': {
            'api_key': st.secrets.get("millionverifier.API_KEY", "")
        },
        'firebase': {
            'type': st.secrets.get("firebase.type", ""),
            'project_id': st.secrets.get("firebase.project_id", ""),
            'private_key_id': st.secrets.get("firebase.private_key_id", ""),
            'private_key': st.secrets.get("firebase.private_key", "").replace('\\n', '\n'),
            'client_email': st.secrets.get("firebase.client_email", ""),
            'client_id': st.secrets.get("firebase.client_id", ""),
            'auth_uri': st.secrets.get("firebase.auth_uri", ""),
            'token_uri': st.secrets.get("firebase.token_uri", ""),
            'auth_provider_x509_cert_url': st.secrets.get("firebase.auth_provider_x509_cert_url", ""),
            'client_x509_cert_url': st.secrets.get("firebase.client_x509_cert_url", "")
        }
    }
    return config

config = load_config()

# Initialize Firebase Storage
def initialize_firebase():
    try:
        creds_dict = {
            "type": config['firebase']['type'],
            "project_id": config['firebase']['project_id'],
            "private_key_id": config['firebase']['private_key_id'],
            "private_key": config['firebase']['private_key'],
            "client_email": config['firebase']['client_email'],
            "client_id": config['firebase']['client_id'],
            "auth_uri": config['firebase']['auth_uri'],
            "token_uri": config['firebase']['token_uri'],
            "auth_provider_x509_cert_url": config['firebase']['auth_provider_x509_cert_url'],
            "client_x509_cert_url": config['firebase']['client_x509_cert_url']
        }
        
        credentials = service_account.Credentials.from_service_account_info(creds_dict)
        storage_client = storage.Client(credentials=credentials)
        
        st.session_state.firebase_storage = storage_client
        st.session_state.firebase_initialized = True
        return storage_client
    except Exception as e:
        st.error(f"Firebase initialization failed: {str(e)}")
        return None

# Initialize SES Client
def initialize_ses():
    try:
        ses_client = boto3.client(
            'ses',
            aws_access_key_id=config['aws']['access_key'],
            aws_secret_access_key=config['aws']['secret_key'],
            region_name=config['aws']['region']
        )
        st.session_state.ses_client = ses_client
        return ses_client
    except Exception as e:
        st.error(f"SES initialization failed: {str(e)}")
        return None

# Journal Data
JOURNALS = [
    "Computer Science and Artificial Intelligence",
    "Advanced Studies in Artificial Intelligence",
    "Advances in Computer Science and Engineering",
    "Far East Journal of Experimental and Theoretical Artificial Intelligence",
    "Advances and Applications in Fluid Mechanics",
    "Advances in Fuzzy Sets and Systems",
    "Far East Journal of Electronics and Communications",
    "Far East Journal of Mechanical Engineering and Physics",
    "International Journal of Nutrition and Dietetics",
    "International Journal of Materials Engineering and Technology",
    "JP Journal of Solids and Structures",
    "Advances and Applications in Discrete Mathematics",
    "Advances and Applications in Statistics",
    "Far East Journal of Applied Mathematics",
    "Far East Journal of Dynamical Systems",
    "Far East Journal of Mathematical Sciences (FJMS)",
    "Far East Journal of Theoretical Statistics",
    "JP Journal of Algebra, Number Theory and Applications",
    "JP Journal of Biostatistics",
    "JP Journal of Fixed Point Theory and Applications",
    "JP Journal of Heat and Mass Transfer",
    "Surveys in Mathematics and Mathematical Sciences",
    "Universal Journal of Mathematics and Mathematical Sciences"
]

# Default email templates
def get_journal_template(journal_name):
    templates = {
        "default": """Dear $$Author_Name$$,

We are pleased to invite you to submit your research work to $$Journal_Name$$. 

Your recent work in $$Department$$ at $$University$$, $$Country$$ aligns well with our journal's scope.

Important Dates:
- Submission Deadline: [Date]
- Notification of Acceptance: [Date]
- Publication Date: [Date]

For submission guidelines, please visit our website: [Journal Website]

We look forward to your valuable contribution.

Best regards,
Editorial Team
$$Journal_Name$$

[Unsubscribe: $$Unsubscribe_Link$$]"""
    }
    return templates.get(journal_name, templates['default'])

# Firebase Storage Functions
def upload_to_firebase(file, file_name, folder="email_lists"):
    if not st.session_state.firebase_initialized:
        initialize_firebase()
    
    try:
        bucket = st.session_state.firebase_storage.bucket()
        blob = bucket.blob(f"{folder}/{file_name}")
        blob.upload_from_string(file.getvalue(), content_type='text/csv')
        return True
    except Exception as e:
        st.error(f"Failed to upload file: {str(e)}")
        return False

def download_from_firebase(file_name, folder="email_lists"):
    if not st.session_state.firebase_initialized:
        initialize_firebase()
    
    try:
        bucket = st.session_state.firebase_storage.bucket()
        blob = bucket.blob(f"{folder}/{file_name}")
        content = blob.download_as_text()
        return content
    except Exception as e:
        st.error(f"Failed to download file: {str(e)}")
        return None

def list_firebase_files(folder="email_lists"):
    if not st.session_state.firebase_initialized:
        initialize_firebase()
    
    try:
        bucket = st.session_state.firebase_storage.bucket()
        blobs = bucket.list_blobs(prefix=folder)
        return [blob.name.split('/')[-1] for blob in blobs if not blob.name.endswith('/')]
    except Exception as e:
        st.error(f"Failed to list files: {str(e)}")
        return []

# Email Functions
def send_ses_email(ses_client, sender, recipient, subject, body_html, body_text, unsubscribe_link):
    try:
        response = ses_client.send_email(
            Source=sender,
            Destination={
                'ToAddresses': [recipient],
            },
            Message={
                'Subject': {
                    'Data': subject,
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': body_text,
                        'Charset': 'UTF-8'
                    },
                    'Html': {
                        'Data': body_html,
                        'Charset': 'UTF-8'
                    }
                }
            },
            Tags=[{
                'Name': 'unsubscribe',
                'Value': unsubscribe_link
            }]
        )
        return response
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")
        return None

# Verification Functions
def verify_email(email, api_key):
    url = f"https://api.millionverifier.com/api/v3/?api={api_key}&email={email}"
    try:
        response = requests.get(url)
        data = response.json()
        return data
    except Exception as e:
        st.error(f"Verification failed: {str(e)}")
        return None

def process_email_list(file, api_key):
    try:
        if isinstance(file, str):
            df = pd.read_csv(StringIO(file))
        else:
            df = pd.read_csv(file)
        
        results = []
        for email in df['email']:
            result = verify_email(email, api_key)
            results.append(result)
            time.sleep(0.1)  # Rate limiting
        
        df['verification_result'] = [r.get('result', 'error') for r in results]
        df['verification_details'] = [str(r) for r in results]
        
        return df
    except Exception as e:
        st.error(f"Failed to process email list: {str(e)}")
        return None

# Analytics Functions
def show_email_analytics(ses_client):
    st.subheader("Email Campaign Analytics")
    
    try:
        stats = ses_client.get_send_statistics()
        datapoints = stats['SendDataPoints']
        
        if not datapoints:
            st.info("No email statistics available yet.")
            return
        
        df = pd.DataFrame(datapoints)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df.set_index('Timestamp', inplace=True)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Delivery Attempts", df['DeliveryAttempts'].sum())
        with col2:
            st.metric("Bounces", df['Bounces'].sum())
        with col3:
            st.metric("Complaints", df['Complaints'].sum())
        
        st.line_chart(df[['DeliveryAttempts', 'Bounces', 'Complaints']])
        
        bounce_response = ses_client.list_bounces()
        if bounce_response['Bounces']:
            st.subheader("Bounce Details")
            bounce_df = pd.DataFrame(bounce_response['Bounces'])
            st.dataframe(bounce_df)
        
    except Exception as e:
        st.error(f"Failed to fetch analytics: {str(e)}")

# Main App
def main():
    st.title("Academic Email Marketing Suite")
    
    # Initialize services
    if not st.session_state.ses_client:
        initialize_ses()
    
    if not st.session_state.firebase_initialized:
        initialize_firebase()
    
    # Navigation
    tab1, tab2 = st.tabs(["Advertisements", "Email Spam Filtration"])
    
    with tab1:
        st.header("Journal Advertisement Campaigns")
        
        # Journal Selection
        col1, col2 = st.columns([3, 1])
        with col1:
            selected_journal = st.selectbox("Select Journal", JOURNALS)
        with col2:
            new_journal = st.text_input("Add New Journal")
            if new_journal and st.button("Add"):
                if new_journal not in JOURNALS:
                    JOURNALS.append(new_journal)
                    st.session_state.selected_journal = new_journal
                    st.experimental_rerun()
        
        st.session_state.selected_journal = selected_journal
        
        # Email Template Editor
        st.subheader("Email Template Editor")
        template = get_journal_template(st.session_state.selected_journal)
        
        col1, col2 = st.columns(2)
        with col1:
            email_subject = st.text_input("Email Subject", 
                                       f"Call for Papers - {st.session_state.selected_journal}")
        
        email_body = st.text_area("Email Body", template, height=300)
        
        st.info("""Available template variables:
        - $$Author_Name$$: Author's full name
        - $$Department$$: Author's department
        - $$University$$: Author's university
        - $$Country$$: Author's country
        - $$Journal_Name$$: Selected journal name
        - $$Unsubscribe_Link$$: Unsubscribe link""")
        
        # File Upload
        st.subheader("Recipient List")
        file_source = st.radio("Select file source", ["Local Upload", "Firebase Storage"])
        
        if file_source == "Local Upload":
            uploaded_file = st.file_uploader("Upload recipient list (CSV)", type=["csv"])
            if uploaded_file:
                df = pd.read_csv(uploaded_file)
                st.dataframe(df.head())
                
                if st.button("Save to Firebase"):
                    if upload_to_firebase(uploaded_file, uploaded_file.name):
                        st.success("File uploaded to Firebase successfully!")
        else:
            if st.button("Refresh File List"):
                st.session_state.firebase_files = list_firebase_files()
            
            if 'firebase_files' in st.session_state and st.session_state.firebase_files:
                selected_file = st.selectbox("Select file from Firebase", st.session_state.firebase_files)
                
                if st.button("Load File"):
                    file_content = download_from_firebase(selected_file)
                    if file_content:
                        df = pd.read_csv(StringIO(file_content))
                        st.session_state.current_recipient_list = df
                        st.dataframe(df.head())
            else:
                st.info("No files found in Firebase Storage")
        
        # Send Options
        if 'current_recipient_list' in st.session_state:
            st.subheader("Send Options")
            
            sender_email = st.text_input("Sender Email (must be verified in SES)")
            unsubscribe_base_url = st.text_input("Unsubscribe Base URL", 
                                               "https://yourdomain.com/unsubscribe?email=")
            
            send_option = st.radio("Send Option", ["Send Now", "Schedule"])
            
            if send_option == "Schedule":
                schedule_time = st.datetime_input("Schedule Time", 
                                                datetime.now() + timedelta(days=1))
            
            if st.button("Start Campaign"):
                if not st.session_state.ses_client:
                    st.error("SES client not initialized. Please configure SES first.")
                    return
                
                df = st.session_state.current_recipient_list
                total_emails = len(df)
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i, row in df.iterrows():
                    email_content = email_body
                    email_content = email_content.replace("$$Author_Name$$", str(row.get('Author Name', '')))
                    email_content = email_content.replace("$$Department$$", str(row.get('Department', '')))
                    email_content = email_content.replace("$$University$$", str(row.get('University', '')))
                    email_content = email_content.replace("$$Country$$", str(row.get('Country', '')))
                    email_content = email_content.replace("$$Journal_Name$$", st.session_state.selected_journal)
                    
                    unsubscribe_link = f"{unsubscribe_base_url}{row.get('email', '')}"
                    email_content = email_content.replace("$$Unsubscribe_Link$$", unsubscribe_link)
                    
                    response = send_ses_email(
                        st.session_state.ses_client,
                        sender_email,
                        row.get('email', ''),
                        email_subject,
                        email_content.replace("\n", "<br>"),
                        email_content,
                        unsubscribe_link
                    )
                    
                    progress = (i + 1) / total_emails
                    progress_bar.progress(progress)
                    status_text.text(f"Processing {i+1} of {total_emails}: {row.get('email', '')}")
                
                st.success(f"Campaign completed! {total_emails} emails sent.")
                show_email_analytics(st.session_state.ses_client)
    
    with tab2:
        st.header("Email Spam Filtration")
        
        # File Upload for Verification
        st.subheader("Email List Verification")
        file_source = st.radio("Select file source for verification", ["Local Upload", "Firebase Storage"])
        
        if file_source == "Local Upload":
            uploaded_file = st.file_uploader("Upload email list for verification (CSV)", type=["csv"])
            if uploaded_file:
                df = pd.read_csv(uploaded_file)
                st.dataframe(df.head())
                
                if st.button("Verify Emails"):
                    if not config['millionverifier']['api_key']:
                        st.error("Please configure MillionVerifier API Key first")
                        return
                    
                    with st.spinner("Verifying emails..."):
                        result_df = process_email_list(uploaded_file, config['millionverifier']['api_key'])
                        if result_df is not None:
                            st.session_state.verified_emails = result_df
                            st.dataframe(result_df)
                            
                            csv = result_df.to_csv(index=False)
                            verified_filename = f"verified_{uploaded_file.name}"
                            st.download_button(
                                "Download Verified List",
                                csv,
                                verified_filename,
                                "text/csv"
                            )
                            
                            if st.button("Save Verified List to Firebase"):
                                if upload_to_firebase(StringIO(csv), verified_filename):
                                    st.success("Verified file uploaded to Firebase!")
        else:
            if st.button("Refresh File List for Verification"):
                st.session_state.firebase_files_verification = list_firebase_files()
            
            if 'firebase_files_verification' in st.session_state and st.session_state.firebase_files_verification:
                selected_file = st.selectbox("Select file to verify from Firebase", 
                                           st.session_state.firebase_files_verification)
                
                if st.button("Load File for Verification"):
                    file_content = download_from_firebase(selected_file)
                    if file_content:
                        df = pd.read_csv(StringIO(file_content))
                        st.session_state.current_verification_list = df
                        st.dataframe(df.head())
                        
                        if st.button("Start Verification"):
                            if not config['millionverifier']['api_key']:
                                st.error("Please configure MillionVerifier API Key first")
                                return
                            
                            with st.spinner("Verifying emails..."):
                                result_df = process_email_list(file_content, config['millionverifier']['api_key'])
                                if result_df is not None:
                                    st.session_state.verified_emails = result_df
                                    st.dataframe(result_df)
                                    
                                    csv = result_df.to_csv(index=False)
                                    verified_filename = f"verified_{selected_file}"
                                    st.download_button(
                                        "Download Verified List",
                                        csv,
                                        verified_filename,
                                        "text/csv"
                                    )
                                    
                                    if st.button("Save Verified List to Firebase"):
                                        if upload_to_firebase(StringIO(csv), verified_filename):
                                            st.success("Verified file uploaded to Firebase!")
            else:
                st.info("No files found in Firebase Storage")
        
        # Verification Analytics
        if 'verified_emails' in st.session_state:
            st.subheader("Verification Analytics")
            df = st.session_state.verified_emails
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Emails", len(df))
            with col2:
                valid = len(df[df['verification_result'] == 'valid'])
                st.metric("Valid Emails", valid)
            with col3:
                invalid = len(df[df['verification_result'] == 'invalid'])
                st.metric("Invalid Emails", invalid)
            
            result_counts = df['verification_result'].value_counts()
            st.bar_chart(result_counts)

if __name__ == "__main__":
    main()
