from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.core.exceptions import ResourceNotFoundError
import os
from datetime import datetime, timedelta

def get_blob_service_client():
    """Returns a BlobServiceClient using the connection string."""
    connection_string = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
    if not connection_string:
        raise ValueError("AZURE_STORAGE_CONNECTION_STRING environment variable not set.")
    return BlobServiceClient.from_connection_string(connection_string)

def upload_blob(file_stream, file_name):
    """Uploads a file to the 'documents' container."""
    blob_service_client = get_blob_service_client()
    container_client = blob_service_client.get_container_client("documents")
    
    # Create container if it doesn't exist
    try:
        container_client.create_container()
    except Exception:
        pass

    blob_client = container_client.get_blob_client(file_name)
    blob_client.upload_blob(file_stream, overwrite=True)
    return blob_client.url

def delete_blob(file_name):
    """Deletes a blob from the 'documents' container."""
    try:
        blob_service_client = get_blob_service_client()
        blob_client = blob_service_client.get_blob_client(container="documents", blob=file_name)
        blob_client.delete_blob()
        return True
    except ResourceNotFoundError:
        return False # Blob not found
    except Exception as e:
        print(f"Error deleting blob {file_name}: {e}")
        return False

def get_blob_sas_url(blob_name):
    """Generates a SAS token for a blob to allow temporary access."""
    blob_service_client = get_blob_service_client()
    account_name = blob_service_client.account_name
    account_key = blob_service_client.credential.account_key

    sas_token = generate_blob_sas(
        account_name=account_name,
        container_name="documents",
        blob_name=blob_name,
        account_key=account_key,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour
    )
    
    blob_url = f"https://{account_name}.blob.core.windows.net/documents/{blob_name}?{sas_token}"
    return blob_url
