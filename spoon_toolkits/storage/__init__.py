"""Storage tools module for SpoonAI."""

from .base_storge_tool import S3Tool
from .aioz.aioz_tools import (
    AiozStorageTool,
    AiozListBucketsTool,
    UploadFileToAiozTool,
    DownloadFileFromAiozTool,
    DeleteAiozObjectTool,
    GenerateAiozPresignedUrlTool,
)
from .oort.oort_tools import (
    OortStorageTool,
    OortCreateBucketTool,
    OortListBucketsTool,
    OortDeleteBucketTool,
    OortListObjectsTool,
    OortUploadFileTool,
    OortDownloadFileTool,
    OortDeleteObjectTool,
    OortDeleteObjectsTool,
    OortGeneratePresignedUrlTool,
)
from .foureverland.foureverland_tools import (
    FourEverlandStorageTool,
    UploadFileToFourEverland,
    ListFourEverlandBuckets,
    DownloadFileFromFourEverland,
    DeleteFourEverlandObject,
    GenerateFourEverlandPresignedUrl,
)

__all__ = [
    "S3Tool",
    "AiozStorageTool",
    "AiozListBucketsTool",
    "UploadFileToAiozTool",
    "DownloadFileFromAiozTool",
    "DeleteAiozObjectTool",
    "GenerateAiozPresignedUrlTool",
    "OortStorageTool",
    "OortCreateBucketTool",
    "OortListBucketsTool",
    "OortDeleteBucketTool",
    "OortListObjectsTool",
    "OortUploadFileTool",
    "OortDownloadFileTool",
    "OortDeleteObjectTool",
    "OortDeleteObjectsTool",
    "OortGeneratePresignedUrlTool",
    "FourEverlandStorageTool",
    "UploadFileToFourEverland",
    "ListFourEverlandBuckets",
    "DownloadFileFromFourEverland",
    "DeleteFourEverlandObject",
    "GenerateFourEverlandPresignedUrl",
]
