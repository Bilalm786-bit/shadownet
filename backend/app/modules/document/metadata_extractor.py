"""
ShadowNet — EXIF & Document Metadata Extractor
Extracts metadata from images, PDFs, and documents — fully offline, no API.
"""

import exifread
import io
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from PyPDF2 import PdfReader
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class DocumentOSINT(OSINTModule):
    name = "document.metadata_extractor"
    description = "Extract EXIF data, GPS coordinates, and metadata from images/PDFs (offline, free)"
    supported_target_types = ["file"]
    requires_api_key = False

    def _extract_image_exif(self, file_data: bytes) -> dict:
        """Extract EXIF data from images."""
        metadata = {}
        try:
            tags = exifread.process_file(io.BytesIO(file_data))
            for tag, value in tags.items():
                if tag not in ("JPEGThumbnail", "TIFFThumbnail"):
                    metadata[str(tag)] = str(value)
        except Exception:
            pass

        # GPS extraction with Pillow
        try:
            img = Image.open(io.BytesIO(file_data))
            exif_data = img._getexif()
            if exif_data:
                gps_info = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == "GPSInfo":
                        for gps_tag_id, gps_value in value.items():
                            gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_info[gps_tag_name] = gps_value
                    else:
                        metadata[str(tag_name)] = str(value)

                if gps_info:
                    metadata["gps_info"] = gps_info
                    lat = self._convert_gps(gps_info.get("GPSLatitude"), gps_info.get("GPSLatitudeRef"))
                    lon = self._convert_gps(gps_info.get("GPSLongitude"), gps_info.get("GPSLongitudeRef"))
                    if lat and lon:
                        metadata["gps_latitude"] = lat
                        metadata["gps_longitude"] = lon
        except Exception:
            pass

        return metadata

    def _convert_gps(self, coords, ref) -> float:
        """Convert GPS coordinates to decimal degrees."""
        if not coords or not ref:
            return None
        try:
            d = float(coords[0])
            m = float(coords[1])
            s = float(coords[2])
            decimal = d + (m / 60.0) + (s / 3600.0)
            if ref in ("S", "W"):
                decimal = -decimal
            return round(decimal, 6)
        except Exception:
            return None

    def _extract_pdf_metadata(self, file_data: bytes) -> dict:
        """Extract metadata from PDF files."""
        metadata = {}
        try:
            reader = PdfReader(io.BytesIO(file_data))
            info = reader.metadata
            if info:
                for key, value in info.items():
                    clean_key = key.lstrip("/")
                    metadata[clean_key] = str(value) if value else None
            metadata["num_pages"] = len(reader.pages)
        except Exception:
            pass
        return metadata

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        file_data = options.get("file_data")
        file_type = options.get("file_type", "image")
        filename = options.get("filename", target)
        entities = []

        if not file_data:
            return ScanResult(
                module=self.name, target=target, success=False,
                error="No file data provided. Pass file_data in options.",
            )

        if isinstance(file_data, str):
            # If path provided, read file
            try:
                with open(file_data, "rb") as f:
                    file_data = f.read()
            except Exception as e:
                return ScanResult(
                    module=self.name, target=target, success=False, error=str(e),
                )

        # Extract metadata based on file type
        if file_type in ("image", "jpg", "jpeg", "png", "tiff"):
            metadata = self._extract_image_exif(file_data)
        elif file_type in ("pdf",):
            metadata = self._extract_pdf_metadata(file_data)
        else:
            metadata = self._extract_image_exif(file_data)
            if not metadata:
                metadata = self._extract_pdf_metadata(file_data)

        # GPS entity
        lat = metadata.get("gps_latitude")
        lon = metadata.get("gps_longitude")
        if lat and lon:
            entities.append(EntityFound(
                entity_type="location",
                value=f"{lat}, {lon}",
                source=self.name, confidence=0.95,
                metadata={"lat": lat, "lon": lon, "source": "EXIF GPS"},
                relationships=[{"type": "PHOTO_TAKEN_AT", "target": filename}],
            ))

        # Software/camera entity
        camera = metadata.get("Image Make", metadata.get("Make", ""))
        model = metadata.get("Image Model", metadata.get("Model", ""))
        software = metadata.get("Image Software", metadata.get("Software", ""))
        author = metadata.get("Author", metadata.get("Creator", ""))

        if author:
            entities.append(EntityFound(
                entity_type="person", value=str(author),
                source=self.name, confidence=0.8,
                metadata={"role": "document_author"},
                relationships=[{"type": "CREATED_BY", "target": filename}],
            ))

        summary_parts = [f"File: {filename}", f"Fields: {len(metadata)}"]
        if lat and lon:
            summary_parts.append(f"📍 GPS: {lat}, {lon}")
        if camera or model:
            summary_parts.append(f"📷 {camera} {model}")
        if author:
            summary_parts.append(f"👤 Author: {author}")

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities, raw_data=metadata,
            summary=" | ".join(summary_parts),
            severity="high" if (lat and lon) else "info",
        )


ModuleRegistry.register(DocumentOSINT())
