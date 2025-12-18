"""
ElevenLabs Audio Tools Demo

Standalone demo of ElevenLabs toolkit capabilities.

Usage:
    export ELEVENLABS_API_KEY="your_key"
    python elevenlabs_demo.py
"""

import asyncio
import base64
import os
import sys
import tempfile
from pathlib import Path


async def demo_tts():
    """Text-to-Speech demo."""
    from spoon_toolkits.audio import ElevenLabsTextToSpeechTool

    print("\n1. Text-to-Speech")
    tts = ElevenLabsTextToSpeechTool()
    result = await tts.execute(
        text="Hello! This is ElevenLabs text to speech.",
        voice_id="JBFqnCBsd6RMkjVDRZzb",
        model_id="eleven_multilingual_v2",
    )

    out = result.output if hasattr(result, "output") else result
    if out.get("success"):
        audio = base64.b64decode(out["audio_base64"])
        path = Path(tempfile.gettempdir()) / "elevenlabs_demo.mp3"
        path.write_bytes(audio)
        print(f"   {len(audio)} bytes -> {path}")
        return str(path)
    else:
        print(f"   Error: {out.get('error')}")
        return None


async def demo_stt(audio_file: str):
    """Speech-to-Text demo."""
    from spoon_toolkits.audio import ElevenLabsSpeechToTextTool

    if not audio_file or not os.path.exists(audio_file):
        print("\n2. Speech-to-Text (skipped - no audio)")
        return

    print("\n2. Speech-to-Text")
    stt = ElevenLabsSpeechToTextTool()
    result = await stt.execute(file_path=audio_file, model_id="scribe_v1")

    out = result.output if hasattr(result, "output") else result
    if out.get("success"):
        print(f"   \"{out['text']}\"")
    else:
        print(f"   Error: {out.get('error')}")


async def demo_stream():
    """Streaming TTS demo."""
    from spoon_toolkits.audio import ElevenLabsTextToSpeechStreamTool

    print("\n3. Streaming TTS with Timestamps")
    streamer = ElevenLabsTextToSpeechStreamTool()
    result = await streamer.execute(
        text="Streaming speech generation with character timing.",
        voice_id="JBFqnCBsd6RMkjVDRZzb",
    )

    out = result.output if hasattr(result, "output") else result
    if out.get("success"):
        print(f"   {out['audio_size_bytes']} bytes, {out.get('total_alignment_points', 0)} alignment points")
    else:
        print(f"   Error: {out.get('error')}")


async def main():
    if not os.getenv("ELEVENLABS_API_KEY"):
        print("Set ELEVENLABS_API_KEY environment variable")
        print("Get your key at: https://elevenlabs.io/app/settings/api-keys")
        sys.exit(1)

    print("ElevenLabs Audio Tools Demo")

    try:
        audio_file = await demo_tts()
        await demo_stt(audio_file)
        await demo_stream()
        print("\nDemo completed!")
    except ImportError as e:
        print(f"Import error: {e}")
        print("Install: pip install spoon-toolkits elevenlabs")


if __name__ == "__main__":
    asyncio.run(main())
