"""Data export and backup management."""

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


class BackupError(Exception):
    """Exception raised for backup errors."""
    pass


@dataclass
class BackupMetadata:
    """Metadata for a backup."""
    
    backup_id: str
    backup_type: str  # "users", "groups", "files", "full"
    created_at: datetime
    backup_path: Path
    item_count: int
    size_bytes: int
    status: str = "completed"  # "in_progress", "completed", "failed"
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BackupManager:
    """Manager for data export and backup operations."""
    
    def __init__(
        self,
        client: GoogleWorkspaceClient,
        backup_dir: Path,
        domain: str,
    ):
        """Initialize backup manager.
        
        Args:
            client: Google Workspace client
            backup_dir: Directory to store backups
            domain: Google Workspace domain
        """
        self.client = client
        self.backup_dir = Path(backup_dir)
        self.domain = domain
        self.logger = logger.bind(component="backup_manager")
        
        # Create backup directory if it doesn't exist
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def backup_users(self, output_format: str = "json") -> BackupMetadata:
        """Backup all user data.
        
        Args:
            output_format: Output format ("json" or "csv")
            
        Returns:
            BackupMetadata object
            
        Raises:
            BackupError: If backup fails
        """
        self.logger.info("starting_user_backup", format=output_format)
        
        backup_id = f"users_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        backup_path = self.backup_dir / f"{backup_id}.{output_format}"
        
        try:
            # Fetch all users
            users = []
            page_token = None
            
            while True:
                response = self.client.admin.users().list(
                    domain=self.domain,
                    maxResults=500,
                    pageToken=page_token,
                    projection="full",
                ).execute()
                
                users.extend(response.get("users", []))
                page_token = response.get("nextPageToken")
                
                if not page_token:
                    break
            
            # Save to file
            if output_format == "json":
                with open(backup_path, "w") as f:
                    json.dump(users, f, indent=2, default=str)
            else:  # CSV
                import csv
                if users:
                    with open(backup_path, "w", newline="") as f:
                        # Extract flat fields
                        fieldnames = ["primaryEmail", "name.fullName", "suspended", "isAdmin", "creationTime", "lastLoginTime"]
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for user in users:
                            writer.writerow({
                                "primaryEmail": user.get("primaryEmail", ""),
                                "name.fullName": user.get("name", {}).get("fullName", ""),
                                "suspended": user.get("suspended", False),
                                "isAdmin": user.get("isAdmin", False),
                                "creationTime": user.get("creationTime", ""),
                                "lastLoginTime": user.get("lastLoginTime", ""),
                            })
            
            # Get file size
            size_bytes = backup_path.stat().st_size
            
            metadata = BackupMetadata(
                backup_id=backup_id,
                backup_type="users",
                created_at=datetime.now(timezone.utc),
                backup_path=backup_path,
                item_count=len(users),
                size_bytes=size_bytes,
                status="completed",
            )
            
            # Save metadata
            self._save_metadata(metadata)
            
            self.logger.info(
                "user_backup_completed",
                backup_id=backup_id,
                user_count=len(users),
                size_bytes=size_bytes,
            )
            
            return metadata
            
        except Exception as e:
            self.logger.error("user_backup_failed", error=str(e))
            raise BackupError(f"Failed to backup users: {e}")
    
    def backup_groups(self, output_format: str = "json") -> BackupMetadata:
        """Backup all group data.
        
        Args:
            output_format: Output format ("json" or "csv")
            
        Returns:
            BackupMetadata object
            
        Raises:
            BackupError: If backup fails
        """
        self.logger.info("starting_group_backup", format=output_format)
        
        backup_id = f"groups_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        backup_path = self.backup_dir / f"{backup_id}.{output_format}"
        
        try:
            # Fetch all groups
            groups = []
            page_token = None
            
            while True:
                response = self.client.admin.groups().list(
                    domain=self.domain,
                    maxResults=200,
                    pageToken=page_token,
                ).execute()
                
                groups.extend(response.get("groups", []))
                page_token = response.get("nextPageToken")
                
                if not page_token:
                    break
            
            # Save to file
            if output_format == "json":
                with open(backup_path, "w") as f:
                    json.dump(groups, f, indent=2, default=str)
            else:  # CSV
                import csv
                if groups:
                    with open(backup_path, "w", newline="") as f:
                        fieldnames = ["email", "name", "description", "directMembersCount"]
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for group in groups:
                            writer.writerow({
                                "email": group.get("email", ""),
                                "name": group.get("name", ""),
                                "description": group.get("description", ""),
                                "directMembersCount": group.get("directMembersCount", 0),
                            })
            
            # Get file size
            size_bytes = backup_path.stat().st_size
            
            metadata = BackupMetadata(
                backup_id=backup_id,
                backup_type="groups",
                created_at=datetime.now(timezone.utc),
                backup_path=backup_path,
                item_count=len(groups),
                size_bytes=size_bytes,
                status="completed",
            )
            
            # Save metadata
            self._save_metadata(metadata)
            
            self.logger.info(
                "group_backup_completed",
                backup_id=backup_id,
                group_count=len(groups),
                size_bytes=size_bytes,
            )
            
            return metadata
            
        except Exception as e:
            self.logger.error("group_backup_failed", error=str(e))
            raise BackupError(f"Failed to backup groups: {e}")
    
    def backup_org_units(self, output_format: str = "json") -> BackupMetadata:
        """Backup all organizational unit data.
        
        Args:
            output_format: Output format ("json" or "csv")
            
        Returns:
            BackupMetadata object
            
        Raises:
            BackupError: If backup fails
        """
        self.logger.info("starting_ou_backup", format=output_format)
        
        backup_id = f"org_units_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        backup_path = self.backup_dir / f"{backup_id}.{output_format}"
        
        try:
            # Fetch all OUs
            response = self.client.admin.orgunits().list(
                customerId="my_customer",
                type="all",
            ).execute()
            
            ous = response.get("organizationUnits", [])
            
            # Save to file
            if output_format == "json":
                with open(backup_path, "w") as f:
                    json.dump(ous, f, indent=2, default=str)
            else:  # CSV
                import csv
                if ous:
                    with open(backup_path, "w", newline="") as f:
                        fieldnames = ["name", "orgUnitPath", "parentOrgUnitPath", "description"]
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for ou in ous:
                            writer.writerow({
                                "name": ou.get("name", ""),
                                "orgUnitPath": ou.get("orgUnitPath", ""),
                                "parentOrgUnitPath": ou.get("parentOrgUnitPath", ""),
                                "description": ou.get("description", ""),
                            })
            
            # Get file size
            size_bytes = backup_path.stat().st_size
            
            metadata = BackupMetadata(
                backup_id=backup_id,
                backup_type="org_units",
                created_at=datetime.now(timezone.utc),
                backup_path=backup_path,
                item_count=len(ous),
                size_bytes=size_bytes,
                status="completed",
            )
            
            # Save metadata
            self._save_metadata(metadata)
            
            self.logger.info(
                "ou_backup_completed",
                backup_id=backup_id,
                ou_count=len(ous),
                size_bytes=size_bytes,
            )
            
            return metadata
            
        except Exception as e:
            self.logger.error("ou_backup_failed", error=str(e))
            raise BackupError(f"Failed to backup organizational units: {e}")
    
    def backup_full(self, output_format: str = "json") -> List[BackupMetadata]:
        """Perform a full backup of all data.
        
        Args:
            output_format: Output format ("json" or "csv")
            
        Returns:
            List of BackupMetadata objects
            
        Raises:
            BackupError: If backup fails
        """
        self.logger.info("starting_full_backup", format=output_format)
        
        backups = []
        
        try:
            # Backup users
            backups.append(self.backup_users(output_format))
            
            # Backup groups
            backups.append(self.backup_groups(output_format))
            
            # Backup OUs
            backups.append(self.backup_org_units(output_format))
            
            self.logger.info("full_backup_completed", backup_count=len(backups))
            return backups
            
        except Exception as e:
            self.logger.error("full_backup_failed", error=str(e))
            raise BackupError(f"Failed to perform full backup: {e}")
    
    def list_backups(self) -> List[BackupMetadata]:
        """List all available backups.
        
        Returns:
            List of BackupMetadata objects
        """
        backups = []
        
        metadata_dir = self.backup_dir / ".metadata"
        if not metadata_dir.exists():
            return backups
        
        for metadata_file in metadata_dir.glob("*.json"):
            try:
                with open(metadata_file) as f:
                    data = json.load(f)
                    metadata = BackupMetadata(
                        backup_id=data["backup_id"],
                        backup_type=data["backup_type"],
                        created_at=datetime.fromisoformat(data["created_at"]),
                        backup_path=Path(data["backup_path"]),
                        item_count=data["item_count"],
                        size_bytes=data["size_bytes"],
                        status=data.get("status", "completed"),
                        error=data.get("error"),
                        metadata=data.get("metadata", {}),
                    )
                    backups.append(metadata)
            except Exception as e:
                self.logger.error("failed_to_load_metadata", file=str(metadata_file), error=str(e))
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x.created_at, reverse=True)
        
        return backups
    
    def _save_metadata(self, metadata: BackupMetadata) -> None:
        """Save backup metadata to disk."""
        metadata_dir = self.backup_dir / ".metadata"
        metadata_dir.mkdir(exist_ok=True)
        
        metadata_file = metadata_dir / f"{metadata.backup_id}.json"
        
        with open(metadata_file, "w") as f:
            json.dump({
                "backup_id": metadata.backup_id,
                "backup_type": metadata.backup_type,
                "created_at": metadata.created_at.isoformat(),
                "backup_path": str(metadata.backup_path),
                "item_count": metadata.item_count,
                "size_bytes": metadata.size_bytes,
                "status": metadata.status,
                "error": metadata.error,
                "metadata": metadata.metadata,
            }, f, indent=2)

