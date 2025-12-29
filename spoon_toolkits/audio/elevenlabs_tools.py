"""
ElevenLabs Audio Tools for Spoon Toolkits

Provides tools for:
- Text-to-Speech (TTS) - Convert text to human-like speech
- Speech-to-Text (STT) - Transcribe audio/video to text
- Voice Design - Generate custom voices from text descriptions
- Voice Cloning - Clone voices from audio samples
- Dubbing - Localize audio/video content to different languages

Requires: ELEVENLABS_API_KEY environment variable
"""

import base64
import logging
import os
from typing import Any, Dict, List, Optional, Union

from pydantic import Field

try:
    from spoon_ai.tools.base import BaseTool, ToolResult
except ImportError:
    from abc import ABC, abstractmethod
    from pydantic import BaseModel

    class BaseTool(ABC, BaseModel):
        name: str = Field(description="The name of the tool")
        description: str = Field(description="A description of the tool")
        parameters: dict = Field(description="The parameters of the tool")

        model_config = {"arbitrary_types_allowed": True}

        async def __call__(self, *args, **kwargs) -> Any:
            return await self.execute(*args, **kwargs)

        @abstractmethod
        async def execute(self, *args, **kwargs) -> Any:
            raise NotImplementedError("Subclasses must implement this method")

    class ToolResult(BaseModel):
        output: Any = Field(default=None)
        error: Optional[str] = Field(default=None)

logger = logging.getLogger(__name__)

# Environment variable key for ElevenLabs API
ELEVENLABS_API_KEY_ENV = "ELEVENLABS_API_KEY"

# Default models
DEFAULT_TTS_MODEL = "eleven_multilingual_v2"
DEFAULT_STT_MODEL = "scribe_v1"
DEFAULT_OUTPUT_FORMAT = "mp3_44100_128"


class ElevenLabsToolBase(BaseTool):
    """Base class for ElevenLabs tools with shared client initialization."""

    _client: Any = None

    def model_post_init(self, __context: Any = None) -> None:
        """Initialize the ElevenLabs client after model creation."""
        super().model_post_init(__context) if hasattr(super(), "model_post_init") else None

    def _get_client(self) -> Any:
        """Get or create the ElevenLabs client."""
        if self._client is None:
            api_key = os.getenv(ELEVENLABS_API_KEY_ENV)
            if not api_key:
                return None
            try:
                from elevenlabs import ElevenLabs
                self._client = ElevenLabs(api_key=api_key)
            except ImportError:
                logger.error("elevenlabs package not installed. Run: pip install elevenlabs")
                return None
            except Exception as e:
                logger.error(f"Failed to initialize ElevenLabs client: {e}")
                return None
        return self._client

    def _check_api_key(self) -> Optional[str]:
        """Check if API key is configured. Returns error message if not."""
        if not os.getenv(ELEVENLABS_API_KEY_ENV):
            return (
                f"ElevenLabs API key not configured. "
                f"Set {ELEVENLABS_API_KEY_ENV} environment variable. "
                f"Get your API key at: https://elevenlabs.io/app/settings/api-keys"
            )
        return None


# =============================================================================
# Text-to-Speech Tools
# =============================================================================


class ElevenLabsTextToSpeechTool(ElevenLabsToolBase):
    """Convert text to speech using ElevenLabs TTS API."""

    name: str = "elevenlabs_text_to_speech"
    description: str = (
        "Convert text to high-quality speech audio using ElevenLabs. "
        "Returns base64-encoded audio data. Supports 70+ languages and 5000+ voices."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The text to convert to speech"
            },
            "voice_id": {
                "type": "string",
                "description": "Voice ID to use. Default: 'JBFqnCBsd6RMkjVDRZzb' (George)",
                "default": "JBFqnCBsd6RMkjVDRZzb"
            },
            "model_id": {
                "type": "string",
                "description": "Model ID. Options: eleven_multilingual_v2, eleven_turbo_v2_5, eleven_flash_v2_5",
                "default": "eleven_multilingual_v2"
            },
            "output_format": {
                "type": "string",
                "description": "Audio format: mp3_44100_128, mp3_22050_32, pcm_16000, pcm_44100",
                "default": "mp3_44100_128"
            },
            "language_code": {
                "type": "string",
                "description": "ISO 639-1 language code (e.g., 'en', 'es', 'zh') to enforce pronunciation"
            },
            "save_to_file": {
                "type": "string",
                "description": "Optional file path to save the audio (e.g., 'output.mp3')"
            }
        },
        "required": ["text"]
    }

    async def execute(
        self,
        text: str,
        voice_id: str = "JBFqnCBsd6RMkjVDRZzb",
        model_id: str = DEFAULT_TTS_MODEL,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
        language_code: Optional[str] = None,
        save_to_file: Optional[str] = None,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Execute text-to-speech conversion."""
        # Validate API key
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            # Generate speech
            audio = client.text_to_speech.convert(
                text=text,
                voice_id=voice_id,
                model_id=model_id,
                output_format=output_format,
                **({"language_code": language_code} if language_code else {})
            )

            # Collect audio bytes from generator
            audio_bytes = b"".join(audio) if hasattr(audio, "__iter__") and not isinstance(audio, bytes) else audio

            # Save to file if requested
            if save_to_file:
                with open(save_to_file, "wb") as f:
                    f.write(audio_bytes)

            # Return base64 encoded audio
            audio_base64 = base64.b64encode(audio_bytes).decode("utf-8")

            result = {
                "success": True,
                "audio_base64": audio_base64,
                "format": output_format,
                "voice_id": voice_id,
                "model_id": model_id,
                "text_length": len(text),
                "audio_size_bytes": len(audio_bytes),
                **({"saved_to": save_to_file} if save_to_file else {}),
                "tool": "elevenlabs_text_to_speech"
            }
            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs TTS failed: {e}")
            error = f"Text-to-speech conversion failed: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


class ElevenLabsTextToSpeechStreamTool(ElevenLabsToolBase):
    """Stream text-to-speech with character-level timestamps."""

    name: str = "elevenlabs_text_to_speech_stream"
    description: str = (
        "Convert text to speech with streaming and character-level timestamps. "
        "Useful for lip-sync, subtitles, and real-time playback applications."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The text to convert to speech"
            },
            "voice_id": {
                "type": "string",
                "description": "Voice ID to use",
                "default": "JBFqnCBsd6RMkjVDRZzb"
            },
            "model_id": {
                "type": "string",
                "description": "Model ID to use",
                "default": "eleven_multilingual_v2"
            },
            "output_format": {
                "type": "string",
                "description": "Audio format",
                "default": "mp3_44100_128"
            }
        },
        "required": ["text"]
    }

    async def execute(
        self,
        text: str,
        voice_id: str = "JBFqnCBsd6RMkjVDRZzb",
        model_id: str = DEFAULT_TTS_MODEL,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Execute streaming text-to-speech with timestamps."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            response = client.text_to_speech.stream_with_timestamps(
                text=text,
                voice_id=voice_id,
                model_id=model_id,
                output_format=output_format,
            )

            # Collect chunks and timestamps
            audio_chunks = []
            alignment_data = []

            for chunk in response:
                # Audio is in audio_base_64 attribute (with underscore)
                if hasattr(chunk, "audio_base_64") and chunk.audio_base_64:
                    audio_chunks.append(base64.b64decode(chunk.audio_base_64))
                # Alignment contains characters and timing
                if hasattr(chunk, "alignment") and chunk.alignment:
                    alignment = chunk.alignment
                    if hasattr(alignment, "characters"):
                        for i, char in enumerate(alignment.characters):
                            alignment_data.append({
                                "char": char,
                                "start": alignment.character_start_times_seconds[i] if hasattr(alignment, "character_start_times_seconds") else None,
                                "end": alignment.character_end_times_seconds[i] if hasattr(alignment, "character_end_times_seconds") else None,
                            })

            audio_bytes = b"".join(audio_chunks)
            audio_base64 = base64.b64encode(audio_bytes).decode("utf-8")

            result = {
                "success": True,
                "audio_base64": audio_base64,
                "alignment": alignment_data[:100] if alignment_data else [],  # Limit for response size
                "total_alignment_points": len(alignment_data),
                "format": output_format,
                "audio_size_bytes": len(audio_bytes),
                "tool": "elevenlabs_text_to_speech_stream"
            }
            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs TTS stream failed: {e}")
            error = f"Text-to-speech streaming failed: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


# =============================================================================
# Speech-to-Text Tools
# =============================================================================


class ElevenLabsSpeechToTextTool(ElevenLabsToolBase):
    """Transcribe audio or video files to text."""

    name: str = "elevenlabs_speech_to_text"
    description: str = (
        "Transcribe audio or video files to text using ElevenLabs STT. "
        "Supports 99 languages with industry-leading accuracy."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the audio or video file to transcribe"
            },
            "model_id": {
                "type": "string",
                "description": "STT model ID. Options: scribe_v1, scribe_v1_experimental, scribe_v2",
                "default": "scribe_v1"
            },
            "language": {
                "type": "string",
                "description": "ISO 639-1 language code (e.g., 'en'). Auto-detected if not specified."
            }
        },
        "required": ["file_path"]
    }

    async def execute(
        self,
        file_path: str,
        model_id: str = DEFAULT_STT_MODEL,
        language: Optional[str] = None,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Execute speech-to-text transcription."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        # Check file exists
        if not os.path.exists(file_path):
            error = f"File not found: {file_path}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            with open(file_path, "rb") as audio_file:
                response = client.speech_to_text.convert(
                    file=audio_file,
                    model_id=model_id,
                    **({"language_code": language} if language else {})
                )

            result = {
                "success": True,
                "text": response.text if hasattr(response, "text") else str(response),
                "language": getattr(response, "language_code", language or "auto-detected"),
                "model_id": model_id,
                "file_path": file_path,
                "tool": "elevenlabs_speech_to_text"
            }

            # Add duration if available
            if hasattr(response, "audio_duration"):
                result["audio_duration_seconds"] = response.audio_duration

            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs STT failed: {e}")
            error = f"Speech-to-text transcription failed: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


# =============================================================================
# Voice Design Tools
# =============================================================================


class ElevenLabsVoiceDesignTool(ElevenLabsToolBase):
    """Design a custom voice from a text description."""

    name: str = "elevenlabs_voice_design"
    description: str = (
        "Generate custom voice previews from a text description. "
        "Describe age, accent, tone, and characteristics to create unique voices."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "voice_description": {
                "type": "string",
                "description": "Description of the voice (e.g., 'A warm elderly British man with a gentle tone')"
            },
            "text": {
                "type": "string",
                "description": "Sample text for the voice preview (100-1000 chars). Auto-generated if not provided."
            },
            "auto_generate_text": {
                "type": "boolean",
                "description": "Auto-generate sample text matching the voice description",
                "default": True
            },
            "output_format": {
                "type": "string",
                "description": "Audio format for previews",
                "default": "mp3_22050_32"
            }
        },
        "required": ["voice_description"]
    }

    async def execute(
        self,
        voice_description: str,
        text: Optional[str] = None,
        auto_generate_text: bool = True,
        output_format: str = "mp3_22050_32",
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Execute voice design to generate voice previews."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            response = client.text_to_voice.design(
                voice_description=voice_description,
                output_format=output_format,
                **({"text": text} if text else {}),
                **({"auto_generate_text": auto_generate_text} if not text else {}),
            )

            # Extract previews
            previews = []
            if hasattr(response, "voice_previews"):
                for preview in response.voice_previews:
                    previews.append({
                        "generated_voice_id": preview.generated_voice_id,
                        "preview_audio_base64": preview.preview_base64 if hasattr(preview, "preview_base64") else None
                    })

            result = {
                "success": True,
                "voice_description": voice_description,
                "previews": previews,
                "preview_count": len(previews),
                "output_format": output_format,
                "note": "Use generated_voice_id with elevenlabs_create_voice_from_preview to save a voice",
                "tool": "elevenlabs_voice_design"
            }
            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs voice design failed: {e}")
            error = f"Voice design failed: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


class ElevenLabsCreateVoiceFromPreviewTool(ElevenLabsToolBase):
    """Create a permanent voice from a voice design preview."""

    name: str = "elevenlabs_create_voice_from_preview"
    description: str = (
        "Save a voice preview (from voice design) as a permanent voice in your library. "
        "Requires a generated_voice_id from the voice design tool."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "generated_voice_id": {
                "type": "string",
                "description": "The generated_voice_id from voice design preview"
            },
            "voice_name": {
                "type": "string",
                "description": "Name for the new voice"
            },
            "voice_description": {
                "type": "string",
                "description": "Description of the voice"
            }
        },
        "required": ["generated_voice_id", "voice_name", "voice_description"]
    }

    async def execute(
        self,
        generated_voice_id: str,
        voice_name: str,
        voice_description: str,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Create a permanent voice from a preview."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            response = client.text_to_voice.create(
                generated_voice_id=generated_voice_id,
                voice_name=voice_name,
                voice_description=voice_description,
            )

            result = {
                "success": True,
                "voice_id": response.voice_id if hasattr(response, "voice_id") else str(response),
                "voice_name": voice_name,
                "voice_description": voice_description,
                "note": "Voice saved! Use the voice_id for text-to-speech",
                "tool": "elevenlabs_create_voice_from_preview"
            }
            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs create voice failed: {e}")
            error = f"Failed to create voice from preview: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


# =============================================================================
# Voice Cloning Tools
# =============================================================================


class ElevenLabsInstantVoiceCloneTool(ElevenLabsToolBase):
    """Clone a voice from audio samples (Instant Voice Clone)."""

    name: str = "elevenlabs_instant_voice_clone"
    description: str = (
        "Create an instant voice clone from audio samples. "
        "Provide 1-3 audio files (MP3/WAV) with clear speech for best results."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name for the cloned voice"
            },
            "files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of audio file paths for cloning (1-3 files recommended)"
            },
            "description": {
                "type": "string",
                "description": "Description of the voice (optional)"
            },
            "remove_background_noise": {
                "type": "boolean",
                "description": "Remove background noise from samples",
                "default": False
            }
        },
        "required": ["name", "files"]
    }

    async def execute(
        self,
        name: str,
        files: List[str],
        description: Optional[str] = None,
        remove_background_noise: bool = False,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Execute instant voice cloning."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        # Validate files exist
        missing_files = [f for f in files if not os.path.exists(f)]
        if missing_files:
            error = f"Audio files not found: {missing_files}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            response = client.voices.ivc.create(
                name=name,
                files=files,
                **({"description": description} if description else {}),
                **({"remove_background_noise": remove_background_noise} if remove_background_noise else {}),
            )

            result = {
                "success": True,
                "voice_id": response.voice_id if hasattr(response, "voice_id") else str(response),
                "voice_name": name,
                "description": description,
                "files_used": files,
                "note": "Voice cloned! Use the voice_id for text-to-speech",
                "tool": "elevenlabs_instant_voice_clone"
            }
            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs voice clone failed: {e}")
            error = f"Instant voice cloning failed: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


# =============================================================================
# Dubbing Tools
# =============================================================================


class ElevenLabsDubbingCreateTool(ElevenLabsToolBase):
    """Create a dubbing project to localize audio/video content."""

    name: str = "elevenlabs_dubbing_create"
    description: str = (
        "Dub audio or video content into a different language. "
        "Upload a file and specify the target language for automatic dubbing."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the audio or video file to dub"
            },
            "target_lang": {
                "type": "string",
                "description": "Target language code (e.g., 'es' for Spanish, 'fr' for French)"
            },
            "source_lang": {
                "type": "string",
                "description": "Source language code (auto-detected if not specified)"
            },
            "name": {
                "type": "string",
                "description": "Name for the dubbing project"
            }
        },
        "required": ["file_path", "target_lang"]
    }

    async def execute(
        self,
        file_path: str,
        target_lang: str,
        source_lang: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Create a dubbing project."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        if not os.path.exists(file_path):
            error = f"File not found: {file_path}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            with open(file_path, "rb") as f:
                response = client.dubbing.create(
                    file=f,
                    target_lang=target_lang,
                    **({"source_lang": source_lang} if source_lang else {}),
                    **({"name": name} if name else {}),
                )

            dubbing_id = response.dubbing_id if hasattr(response, "dubbing_id") else str(response)

            result = {
                "success": True,
                "dubbing_id": dubbing_id,
                "target_lang": target_lang,
                "source_lang": source_lang or "auto-detected",
                "file_path": file_path,
                "status": "created",
                "note": "Use elevenlabs_dubbing_status to check progress, then elevenlabs_dubbing_audio to download",
                "tool": "elevenlabs_dubbing_create"
            }
            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs dubbing create failed: {e}")
            error = f"Dubbing project creation failed: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


class ElevenLabsDubbingStatusTool(ElevenLabsToolBase):
    """Check the status of a dubbing project."""

    name: str = "elevenlabs_dubbing_status"
    description: str = "Check the status and progress of an existing dubbing project."
    parameters: dict = {
        "type": "object",
        "properties": {
            "dubbing_id": {
                "type": "string",
                "description": "The dubbing project ID"
            }
        },
        "required": ["dubbing_id"]
    }

    async def execute(
        self,
        dubbing_id: str,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Get dubbing project status."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            response = client.dubbing.get(dubbing_id=dubbing_id)

            result = {
                "success": True,
                "dubbing_id": dubbing_id,
                "status": response.status if hasattr(response, "status") else "unknown",
                "target_languages": getattr(response, "target_languages", []),
                "tool": "elevenlabs_dubbing_status"
            }

            # Add any additional info
            if hasattr(response, "error"):
                result["error_message"] = response.error

            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs dubbing status failed: {e}")
            error = f"Failed to get dubbing status: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


class ElevenLabsDubbingAudioTool(ElevenLabsToolBase):
    """Download dubbed audio from a completed dubbing project."""

    name: str = "elevenlabs_dubbing_audio"
    description: str = (
        "Download the dubbed audio for a specific language from a completed dubbing project. "
        "Returns base64-encoded audio or saves to a file."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "dubbing_id": {
                "type": "string",
                "description": "The dubbing project ID"
            },
            "language_code": {
                "type": "string",
                "description": "The target language code to download (e.g., 'es')"
            },
            "save_to_file": {
                "type": "string",
                "description": "Optional file path to save the dubbed audio"
            }
        },
        "required": ["dubbing_id", "language_code"]
    }

    async def execute(
        self,
        dubbing_id: str,
        language_code: str,
        save_to_file: Optional[str] = None,
    ) -> Union[ToolResult, Dict[str, Any]]:
        """Download dubbed audio."""
        if error := self._check_api_key():
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        client = self._get_client()
        if not client:
            error = "Failed to initialize ElevenLabs client"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}

        try:
            audio_stream = client.dubbing.audio.get(
                dubbing_id=dubbing_id,
                language_code=language_code,
            )

            # Collect audio bytes
            audio_bytes = b"".join(audio_stream) if hasattr(audio_stream, "__iter__") and not isinstance(audio_stream, bytes) else audio_stream

            # Save to file if requested
            if save_to_file:
                with open(save_to_file, "wb") as f:
                    f.write(audio_bytes)

            audio_base64 = base64.b64encode(audio_bytes).decode("utf-8")

            result = {
                "success": True,
                "dubbing_id": dubbing_id,
                "language_code": language_code,
                "audio_base64": audio_base64,
                "audio_size_bytes": len(audio_bytes),
                **({"saved_to": save_to_file} if save_to_file else {}),
                "tool": "elevenlabs_dubbing_audio"
            }
            return ToolResult(output=result) if hasattr(ToolResult, "output") else result

        except Exception as e:
            logger.error(f"ElevenLabs dubbing audio failed: {e}")
            error = f"Failed to download dubbed audio: {str(e)}"
            return ToolResult(error=error) if hasattr(ToolResult, "error") else {"success": False, "error": error}


__all__ = [
    # Base
    "ElevenLabsToolBase",
    # Text-to-Speech
    "ElevenLabsTextToSpeechTool",
    "ElevenLabsTextToSpeechStreamTool",
    # Speech-to-Text
    "ElevenLabsSpeechToTextTool",
    # Voice Design
    "ElevenLabsVoiceDesignTool",
    "ElevenLabsCreateVoiceFromPreviewTool",
    # Voice Clone
    "ElevenLabsInstantVoiceCloneTool",
    # Dubbing
    "ElevenLabsDubbingCreateTool",
    "ElevenLabsDubbingStatusTool",
    "ElevenLabsDubbingAudioTool",
]

