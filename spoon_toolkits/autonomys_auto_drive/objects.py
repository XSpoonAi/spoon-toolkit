import os.path

from fastmcp import FastMCP
from .http_client import autonomys_auto_drive_client

mcp = FastMCP("AutonomysAutoDriveObjects")
mcp_management = FastMCP("AutonomysAutoDriveObjectsManagement")

@mcp.tool()
# @time_cache()
async def search_for_files(filename_or_cid: str, user_only: bool = True, limit: int = 1) -> dict:
    """
    Search for files by filename_or_cid.
    filename_or_cid can be either a filename or a cid.
    if user_only is False, searches globally for all users' files
    limit should be greater than zero
    Returns in the following format:
    [
      {
        "cid": "string",
        "name": "string"
      }
    ]
    """
    r = await autonomys_auto_drive_client.get(f'/objects/search?cid={filename_or_cid}&scope={"user" if user_only else "global"}&limit={limit}')
    r = r.json()
    return r

@mcp.tool()
# @time_cache()
async def download_file_to_path(filename_and_path: str, cid: str) -> None:
    """
    Download file by cid.
    """
    if os.path.isfile(filename_and_path):
        raise ValueError(f'File {filename_and_path} already exists')
    r = await autonomys_auto_drive_client.get(f"/downloads/{cid}")
    r = r.content
    with open(filename_and_path, 'wb') as f:
        f.write(r)

@mcp.tool()
# @time_cache()
async def download_file_to_path(filename_and_path: str, cid: str) -> None:
    """
    Download file by cid.
    limit should be greater than zero
    Returns in the following format:
    [
      {
        "cid": "string",
        "name": "string"
      }
    ]
    """
    if os.path.isfile(filename_and_path):
        raise ValueError(f'File {filename_and_path} already exists')
    r = await autonomys_auto_drive_client.get(f"/downloads/{cid}")
    r = r.content
    with open(filename_and_path, 'wb') as f:
        f.write(r)

@mcp.tool()
async def get_file_info(cid: str) -> dict:
    """
    Get already-uploaded file info by cid
    {
      "headCid": "string",
      "name": "string",
      "size": "string",
      "owners": [
        {
          "oauthProvider": "string",
          "oauthUserId": "string",
          "role": "admin"
        }
      ],
      "uploadStatus": {
        "uploadedNodes": 0,
        "totalNodes": 0,
        "archivedNodes": 0,
        "minimumBlockDepth": 0,
        "maximumBlockDepth": 0
      },
      "createdAt": "string",
      "type": "file",
      "mimeType": "string",
      "children": [
        {}
      ],
      "type": "file",
      "dataCid": "string",
      "name": "string",
      "mimeType": "string",
      "totalSize": "string",
      "totalChunks": 0,
      "chunks": [
        {
          "size": "string",
          "cid": "string"
        }
      ],
      "uploadOptions": {
        "compression": {
          "algorithm": "ZLIB",
          "level": 8
        },
        "encryption": {
          "algorithm": "AES_256_GCM",
          "chunkSize": 1024
        }
      },
      "uploadedNodes": 0,
      "totalNodes": 0,
      "archivedNodes": 0,
      "minimumBlockDepth": 0,
      "maximumBlockDepth": 0
    }
    """
    summary = await autonomys_auto_drive_client.get(f"/objects/{cid}/summary")
    summary = summary.json()
    metadata = await autonomys_auto_drive_client.get(f"/objects/{cid}/metadata")
    metadata = metadata.json()
    upload_status = await autonomys_auto_drive_client.get(f"/objects/{cid}/status")
    upload_status = upload_status.json()
    merged_info = {**summary, **metadata, **upload_status}
    return merged_info

@mcp_management.tool()
async def delete_object(cid: str) -> None:
    """
    Delete a file uploaded to autonomys auto drive. This does not delete any local file on our computer.
    """
    await autonomys_auto_drive_client.post(f"/objects/{cid}/delete")

@mcp_management.tool()
async def restore_deleted_object(cid: str) -> None:
    """
    Restore a deleted file uploaded to autonomys auto drive. This does not delete or restore any local file on our computer.
    """
    await autonomys_auto_drive_client.post(f"/objects/{cid}/restore")

# @mcp_management.tool()
# async def share_object(cid: str) -> None:
#     """
#     Share a file uploaded to autonomys auto drive.
#     """  # return value is unknown for now
#     await autonomys_auto_drive_client.post(f"/objects/{cid}/share")