from fastapi import APIRouter, HTTPException, status
from pydantic import UUID4
from starlette.responses import FileResponse
from pathlib import Path

from mealie.schema.user import PrivateUser

router = APIRouter(prefix="/users")


@router.get("/{user_id}/{file_name}", response_class=FileResponse)
async def get_user_image(user_id: UUID4, file_name: str):
    """Serve a user's image file, preventing path traversal outside the user directory."""
    user_dir = PrivateUser.get_directory(user_id)

    # Disallow absolute paths and parent directory traversal
    candidate = (user_dir / file_name).resolve()
    try:
        user_dir_resolved = user_dir.resolve()
    except Exception:
        user_dir_resolved = Path(user_dir)

    if not str(candidate).startswith(str(user_dir_resolved) + str(Path("/") )):
        # Fallback safe check for platforms without commonpath
        try:
            from os.path import commonpath
            if commonpath([str(candidate), str(user_dir_resolved)]) != str(user_dir_resolved):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid file path")
        except Exception:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid file path")

    if candidate.exists() and candidate.is_file():
        return FileResponse(candidate, media_type="image/webp")
    else:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
