import os
import dropbox
from flask import current_app

def get_dropbox_client():
    return dropbox.Dropbox(current_app.config['DROPBOX_ACCESS_TOKEN'])

def upload_file_to_dropbox(file_path):
    dbx = get_dropbox_client()
    filename = os.path.basename(file_path)
    upload_path = current_app.config['DROPBOX_UPLOAD_PATH'] + filename

    try:
        with open(file_path, 'rb') as file:
            dbx.files_upload(file.read(), upload_path, mode=dropbox.files.WriteMode('overwrite'))

        # Obtenha o link de compartilhamento público
        shared_link_metadata = dbx.sharing_create_shared_link_with_settings(upload_path)
        return shared_link_metadata.url
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {file_path}")
        return None
    except dropbox.exceptions.ApiError as e:
        print(f"Erro ao enviar o arquivo para o Dropbox: {e}")
        return None
