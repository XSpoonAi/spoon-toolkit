import asyncio
from fastmcp import FastMCP
import os
from .mime_type import suffix_to_mime_type_dict
from .http_client import autonomys_auto_drive_client

mcp = FastMCP("AutonomysAutoDriveUploads")
chunk_size_bytes = 1024**2

@mcp.tool()
async def upload_file(file_and_path: str) -> dict:
    """
    Upload a file at the specified path on the computer.
    The response of the request should be like
    {
      "cid": "string"
    }
    """
    if not os.path.isfile(file_and_path):
        raise ValueError(f"No file at path {file_and_path}")
    _, suffix = os.path.splitext(file_and_path)
    base_name = os.path.basename(file_and_path)
    mime_type = suffix_to_mime_type_dict.get(suffix, 'application/octet-stream')
    r = await autonomys_auto_drive_client.post(
        r'/uploads/file', headers={'Content-Type': 'application/json'},
        json={
          "filename": base_name,
          "mimeType": mime_type,
          "uploadOptions": {
            # "compression": {
            #   "algorithm": "ZLIB",
            #   "level": 8
            # },
            # "encryption": {
            #   "algorithm": "AES_256_GCM",
            #   "chunkSize": 1024
            # }
          }
        }
    )
    r = r.json()
    upload_id = r['id']
    index = 0
    with open(file_and_path, 'rb') as f:
        while 1:
            file_chunk = f.read(chunk_size_bytes)
            if not file_chunk:
                break
            # formdata = {
            #     'file': file_chunk,
            #     'index': str(index)
            # }
            # r = await autonomys_auto_drive_client.post(
            #     f'/uploads/file/{upload_id}/chunk',# headers={'Content-Type': 'multipart/form-data'},
            #     data=formdata
            # )
            files = {'file': ('blob', file_chunk, 'application/octet-stream')}
            data = {'index': str(index)}
            r = await autonomys_auto_drive_client.post(
                f'/uploads/file/{upload_id}/chunk',
                files=files, data=data
            )
            # index += chunk_size_bytes  # this is wrong
            index += 1
    r = await autonomys_auto_drive_client.post(
        f'/uploads/{upload_id}/complete', headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
    )
    r = r.json()
    return r

def test_upload_file():
    asyncio.run(upload_file('__init__.py'))