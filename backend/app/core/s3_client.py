"""
ShadowNet — MinIO/S3 Client
Gracefully degrades if boto3 package is not installed.
"""

from typing import Optional
import structlog
import io

logger = structlog.get_logger(__name__)

try:
    import boto3
    from botocore.client import Config
    HAS_S3 = True
except ImportError:
    HAS_S3 = False
    logger.warning("boto3 package not installed — S3 storage disabled")


class S3Client:
    _client = None
    _available = False

    @classmethod
    def connect(cls):
        if not HAS_S3:
            logger.info("MinIO/S3 skipped (boto3 not installed)")
            return
        from app.core.config import settings
        try:
            cls._client = boto3.client(
                "s3",
                endpoint_url=f"http://{settings.minio_endpoint}",
                aws_access_key_id=settings.minio_access_key,
                aws_secret_access_key=settings.minio_secret_key,
                config=Config(signature_version="s3v4"),
                region_name="us-east-1",
            )
            try:
                cls._client.head_bucket(Bucket=settings.minio_bucket)
            except Exception:
                cls._client.create_bucket(Bucket=settings.minio_bucket)
            cls._available = True
            logger.info("MinIO/S3 connected", endpoint=settings.minio_endpoint)
        except Exception as e:
            logger.warning("MinIO/S3 connection failed", error=str(e))

    @classmethod
    def upload_file(cls, file_data: bytes, object_key: str, content_type: str = "application/octet-stream") -> str:
        if not cls._available:
            return object_key
        from app.core.config import settings
        cls._client.put_object(Bucket=settings.minio_bucket, Key=object_key, Body=io.BytesIO(file_data), ContentType=content_type, ContentLength=len(file_data))
        return object_key

    @classmethod
    def download_file(cls, object_key: str) -> bytes:
        if not cls._available:
            return b""
        from app.core.config import settings
        response = cls._client.get_object(Bucket=settings.minio_bucket, Key=object_key)
        return response["Body"].read()

    @classmethod
    def get_presigned_url(cls, object_key: str, expires_in: int = 3600) -> str:
        if not cls._available:
            return ""
        from app.core.config import settings
        return cls._client.generate_presigned_url("get_object", Params={"Bucket": settings.minio_bucket, "Key": object_key}, ExpiresIn=expires_in)

    @classmethod
    def delete_file(cls, object_key: str):
        if not cls._available:
            return
        from app.core.config import settings
        cls._client.delete_object(Bucket=settings.minio_bucket, Key=object_key)

    @classmethod
    def list_files(cls, prefix: str = "") -> list:
        if not cls._available:
            return []
        from app.core.config import settings
        response = cls._client.list_objects_v2(Bucket=settings.minio_bucket, Prefix=prefix)
        return [obj["Key"] for obj in response.get("Contents", [])]
