import streamlit as st
import boto3
import pandas as pd
import datetime
import time
import requests
import json
import os
from datetime import datetime, timedelta
from pytz import timezone
import pyrebase
from io import StringIO

# App Configuration
st.set_page_config(page_title="Email Marketing Suite", layout="wide")

# Initialize session state variables
if 'ses_client' not in st.session_state:
    st.session_state.ses_client = None
if 'firebase' not in st.session_state:
    st.session_state.firebase = None
if 'firebase_initialized' not in st.session_state:
    st.session_state.firebase_initialized = False
if 'selected_journal' not in st.session_state:
    st.session_state.selected_journal = None

# Firebase Configuration (replace with your actual config)
firebase_config = {
    "apiKey": "your-api-key",
    "authDomain": "your-project.firebaseapp.com",
    "databaseURL": "https://your-project.firebaseio.com",
    "projectId": "your-project",
    "storageBucket": "your-project.appspot.com",
    "messagingSenderId": "your-sender-id",
    "appId": "your-app-id"
}

# Initialize Firebase
def initialize_firebase():
    try:
        firebase = pyrebase.initialize_app(firebase_config)
        auth = firebase.auth()
        # You can sign in anonymously or with email/password
        user = auth.sign_in_anonymous()
        st.session_state.firebase = firebase
        st.session_state.firebase_initialized = True
        return firebase
    except Exception as e:
        st.error(f"Firebase initialization failed: {str(e)}")
        return None

# Initialize SES Client
def initialize_ses(aws_access_key, aws_secret_key, region='us-east-1'):
    try:
        ses_client = boto3.client(
            'ses',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
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

# Default email templates for each journal
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

# Function to upload file to Firebase Storage
def upload_to_firebase(file, file_name, folder="email_lists"):
    if not st.session_state.firebase_initialized:
        initialize_firebase()
    
    try:
        storage = st.session_state.firebase.storage()
        path = f"{folder}/{file_name}"
        storage.child(path).put(file)
        return True
    except Exception as e:
        st.error(f"Failed to upload file: {str(e)}")
        return False

# Function to download file from Firebase Storage
def download_from_firebase(file_name, folder="email_lists"):
    if not st.session_state.firebase_initialized:
        initialize_firebase()
    
    try:
        storage = st.session_state.firebase.storage()
        path = f"{folder}/{file_name}"
        url = storage.child(path).get_url(None)
        return url
    except Exception as e:
        st.error(f"Failed to download file: {str(e)}")
        return None

# Function to list files in Firebase Storage
def list_firebase_files(folder="email_lists"):
    if not st.session_state.firebase_initialized:
        initialize_firebase()
    
    try:
        storage = st.session_state.firebase.storage()
        files = storage.child(folder).list_files()
        return [file.name.split('/')[-1] for file in files]
    except Exception as e:
        st.error(f"Failed to list files: {str(e)}")
        return []

# Function to send email via SES
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

# Function to verify email with MillionVerifier
def verify_email(email, api_key):
    url = f"https://api.millionverifier.com/api/v3/?api={api_key}&email={email}"
    try:
        response = requests.get(url)
        data = response.json()
        return data
    except Exception as e:
        st.error(f"Verification failed: {str(e)}")
        return None

# Function to process email list with MillionVerifier
def process_email_list(file, api_key):
    try:
        # Read the file
        if isinstance(file, str):
            df = pd.read_csv(file)
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

# Dashboard for email analytics
def show_email_analytics(ses_client):
    st.subheader("Email Campaign Analytics")
    
    try:
        # Get send statistics
        stats = ses_client.get_send_statistics()
        datapoints = stats['SendDataPoints']
        
        if not datapoints:
            st.info("No email statistics available yet.")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(datapoints)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df.set_index('Timestamp', inplace=True)
        
        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Delivery Attempts", df['DeliveryAttempts'].sum())
        with col2:
            st.metric("Bounces", df['Bounces'].sum())
        with col3:
            st.metric("Complaints", df['Complaints'].sum())
        
        # Display time series chart
        st.line_chart(df[['DeliveryAttempts', 'Bounces', 'Complaints']])
        
        # Display bounce reasons (if any)
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
    
    # Navigation
    tab1, tab2 = st.tabs(["Advertisements", "Email Spam Filtration"])
    
    with tab1:
        st.header("Journal Advertisement Campaigns")
        
        # SES Configuration
        with st.expander("Amazon SES Configuration", expanded=False):
            aws_access_key = st.text_input("AWS Access Key ID", type="password")
            aws_secret_key = st.text_input("AWS Secret Access Key", type="password")
            region = st.selectbox("AWS Region", ["us-east-1", "us-west-2", "eu-west-1"])
            
            if st.button("Initialize SES"):
                if aws_access_key and aws_secret_key:
                    ses_client = initialize_ses(aws_access_key, aws_secret_key, region)
                    if ses_client:
                        st.success("SES client initialized successfully!")
                else:
                    st.error("Please provide both AWS Access Key and Secret Key")
        
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
        
        # Template variables help
        st.info("""
        Available template variables:
        - $$Author_Name$$: Author's full name
        - $$Department$$: Author's department
        - $$University$$: Author's university
        - $$Country$$: Author's country
        - $$Journal_Name$$: Selected journal name
        - $$Unsubscribe_Link$$: Unsubscribe link
        """)
        
        # File Upload
        st.subheader("Recipient List")
        file_source = st.radio("Select file source", ["Local Upload", "Firebase Storage"])
        
        if file_source == "Local Upload":
            uploaded_file = st.file_uploader("Upload recipient list (CSV)", type=["csv"])
            if uploaded_file:
                df = pd.read_csv(uploaded_file)
                st.dataframe(df.head())
                
                # Option to save to Firebase
                if st.button("Save to Firebase"):
                    if upload_to_firebase(uploaded_file, uploaded_file.name):
                        st.success("File uploaded to Firebase successfully!")
        else:
            # List files from Firebase
            if st.button("Refresh File List"):
                st.session_state.firebase_files = list_firebase_files()
            
            if 'firebase_files' in st.session_state and st.session_state.firebase_files:
                selected_file = st.selectbox("Select file from Firebase", st.session_state.firebase_files)
                
                if st.button("Load File"):
                    file_url = download_from_firebase(selected_file)
                    if file_url:
                        df = pd.read_csv(file_url)
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
                    # Replace template variables
                    email_content = email_body
                    email_content = email_content.replace("$$Author_Name$$", str(row.get('Author Name', '')))
                    email_content = email_content.replace("$$Department$$", str(row.get('Department', '')))
                    email_content = email_content.replace("$$University$$", str(row.get('University', '')))
                    email_content = email_content.replace("$$Country$$", str(row.get('Country', '')))
                    email_content = email_content.replace("$$Journal_Name$$", st.session_state.selected_journal)
                    
                    unsubscribe_link = f"{unsubscribe_base_url}{row.get('email', '')}"
                    email_content = email_content.replace("$$Unsubscribe_Link$$", unsubscribe_link)
                    
                    # Send email
                    response = send_ses_email(
                        st.session_state.ses_client,
                        sender_email,
                        row.get('email', ''),
                        email_subject,
                        email_content.replace("\n", "<br>"),  # Simple HTML conversion
                        email_content,
                        unsubscribe_link
                    )
                    
                    # Update progress
                    progress = (i + 1) / total_emails
                    progress_bar.progress(progress)
                    status_text.text(f"Processing {i+1} of {total_emails}: {row.get('email', '')}")
                
                st.success(f"Campaign completed! {total_emails} emails sent.")
                
                # Show analytics
                show_email_analytics(st.session_state.ses_client)
    
    with tab2:
        st.header("Email Spam Filtration")
        
        # MillionVerifier Configuration
        with st.expander("MillionVerifier Configuration", expanded=False):
            mv_api_key = st.text_input("MillionVerifier API Key", type="password")
            
            if st.button("Test API Connection"):
                if mv_api_key:
                    test_email = "test@example.com"
                    result = verify_email(test_email, mv_api_key)
                    if result:
                        st.success(f"API Connection Successful! Response: {result.get('result', 'Unknown')}")
                    else:
                        st.error("API Connection Failed")
                else:
                    st.error("Please provide API Key")
        
        # File Upload for Verification
        st.subheader("Email List Verification")
        file_source = st.radio("Select file source for verification", ["Local Upload", "Firebase Storage"])
        
        if file_source == "Local Upload":
            uploaded_file = st.file_uploader("Upload email list for verification (CSV)", type=["csv"])
            if uploaded_file:
                df = pd.read_csv(uploaded_file)
                st.dataframe(df.head())
                
                if st.button("Verify Emails"):
                    if not mv_api_key:
                        st.error("Please configure MillionVerifier API Key first")
                        return
                    
                    with st.spinner("Verifying emails..."):
                        result_df = process_email_list(uploaded_file, mv_api_key)
                        if result_df is not None:
                            st.session_state.verified_emails = result_df
                            st.dataframe(result_df)
                            
                            # Save verified file
                            csv = result_df.to_csv(index=False)
                            verified_filename = f"verified_{uploaded_file.name}"
                            st.download_button(
                                "Download Verified List",
                                csv,
                                verified_filename,
                                "text/csv"
                            )
                            
                            # Option to save to Firebase
                            if st.button("Save Verified List to Firebase"):
                                if upload_to_firebase(csv, verified_filename):
                                    st.success("Verified file uploaded to Firebase!")
        else:
            # List files from Firebase
            if st.button("Refresh File List for Verification"):
                st.session_state.firebase_files_verification = list_firebase_files()
            
            if 'firebase_files_verification' in st.session_state and st.session_state.firebase_files_verification:
                selected_file = st.selectbox("Select file to verify from Firebase", 
                                           st.session_state.firebase_files_verification)
                
                if st.button("Load File for Verification"):
                    file_url = download_from_firebase(selected_file)
                    if file_url:
                        df = pd.read_csv(file_url)
                        st.session_state.current_verification_list = df
                        st.dataframe(df.head())
                        
                        if st.button("Start Verification"):
                            if not mv_api_key:
                                st.error("Please configure MillionVerifier API Key first")
                                return
                            
                            with st.spinner("Verifying emails..."):
                                result_df = process_email_list(file_url, mv_api_key)
                                if result_df is not None:
                                    st.session_state.verified_emails = result_df
                                    st.dataframe(result_df)
                                    
                                    # Save verified file
                                    csv = result_df.to_csv(index=False)
                                    verified_filename = f"verified_{selected_file}"
                                    st.download_button(
                                        "Download Verified List",
                                        csv,
                                        verified_filename,
                                        "text/csv"
                                    )
                                    
                                    # Option to save to Firebase
                                    if st.button("Save Verified List to Firebase"):
                                        if upload_to_firebase(csv, verified_filename):
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
            
            # Pie chart of results
            result_counts = df['verification_result'].value_counts()
            st.bar_chart(result_counts)

if __name__ == "__main__":
    main()