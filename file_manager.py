"""
File Manager Module
Handles all file storage operations with configurable paths.
"""
import os
import pathlib
from typing import Optional, Tuple
import config


class FileManager:
    """Manages file storage operations with dynamic path configuration."""
    
    def __init__(self, upload_directory: Optional[str] = None):
        """
        Initialize FileManager with upload directory.
        
        Args:
            upload_directory: Custom upload directory path. If None, uses config.UPLOAD_DIRECTORY
        """
        self.upload_directory = upload_directory or config.UPLOAD_DIRECTORY
        self.permanent_prefix = config.PERMANENT_FILE_PREFIX
        self.conversion_input_prefix = config.CONVERSION_INPUT_PREFIX
        
        # Ensure upload directory exists
        self._ensure_directory_exists(self.upload_directory)
    
    def _ensure_directory_exists(self, directory: str) -> None:
        """Create directory if it doesn't exist."""
        path = pathlib.Path(directory)
        path.mkdir(parents=True, exist_ok=True)
    
    def get_file_path(self, filename: str, permanent: bool = False) -> str:
        """
        Get full path for a file.
        
        Args:
            filename: Name of the file
            permanent: Whether this is a permanent file (adds PERM_ prefix)
            
        Returns:
            Full path to the file
        """
        if permanent:
            filename = f"{self.permanent_prefix}{filename}"
        
        return os.path.join(self.upload_directory, filename)
    
    def get_conversion_input_path(self, filename: str) -> str:
        """
        Get full path for a conversion input file.
        
        Args:
            filename: Original filename
            
        Returns:
            Full path with conversion prefix
        """
        prefixed_filename = f"{self.conversion_input_prefix}{filename}"
        return os.path.join(self.upload_directory, prefixed_filename)
    
    def get_conversion_output_path(self, filename_without_ext: str, output_ext: str, permanent: bool = False) -> str:
        """
        Get full path for a conversion output file.
        
        Args:
            filename_without_ext: Filename without extension
            output_ext: Output file extension
            permanent: Whether this is a permanent file
            
        Returns:
            Full path to the output file
        """
        output_filename = f"{filename_without_ext}.{output_ext}"
        return self.get_file_path(output_filename, permanent=permanent)
    
    def is_permanent_file(self, filename: str) -> bool:
        """
        Check if a filename indicates a permanent file.
        
        Args:
            filename: Filename to check
            
        Returns:
            True if file has permanent prefix
        """
        return filename.startswith(self.permanent_prefix)
    
    def validate_filename(self, filename: str, allow_permanent_prefix: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate filename for upload.
        
        Args:
            filename: Filename to validate
            allow_permanent_prefix: Whether PERM_ prefix is allowed in the filename
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not filename:
            return False, "Filename cannot be empty"
        
        if not allow_permanent_prefix and self.permanent_prefix in filename:
            return False, f"Filename cannot contain '{self.permanent_prefix}' for regular uploads"
        
        # Check for path traversal attempts
        if ".." in filename or "/" in filename or "\\" in filename:
            return False, "Invalid filename: path traversal not allowed"
        
        return True, None
    
    def list_files(self, permanent_only: bool = False, exclude_conversion_inputs: bool = True) -> list[str]:
        """
        List files in the upload directory.
        
        Args:
            permanent_only: Only return permanent files
            exclude_conversion_inputs: Exclude conversion input files from results
            
        Returns:
            List of filenames
        """
        try:
            all_files = os.listdir(self.upload_directory)
            
            files = []
            for filename in all_files:
                # Skip conversion input files if requested
                if exclude_conversion_inputs and filename.startswith(self.conversion_input_prefix):
                    continue
                
                # Filter permanent files if requested
                if permanent_only and not filename.startswith(self.permanent_prefix):
                    continue
                
                # Only include files (not directories)
                full_path = os.path.join(self.upload_directory, filename)
                if os.path.isfile(full_path):
                    files.append(filename)
            
            return sorted(files)
        except FileNotFoundError:
            return []
    
    def file_exists(self, filename: str, permanent: bool = False) -> bool:
        """
        Check if a file exists.
        
        Args:
            filename: Name of the file
            permanent: Whether to check for permanent file
            
        Returns:
            True if file exists
        """
        file_path = self.get_file_path(filename, permanent=permanent)
        return os.path.isfile(file_path)
    
    def delete_file(self, filename: str, permanent: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Delete a file.
        
        Args:
            filename: Name of the file to delete
            permanent: Whether this is a permanent file
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            file_path = self.get_file_path(filename, permanent=permanent)
            
            if not os.path.exists(file_path):
                return False, "File not found"
            
            os.remove(file_path)
            return True, None
        except Exception as e:
            return False, str(e)
    
    def get_file_size(self, filename: str, permanent: bool = False) -> Optional[int]:
        """
        Get size of a file in bytes.
        
        Args:
            filename: Name of the file
            permanent: Whether this is a permanent file
            
        Returns:
            File size in bytes, or None if file doesn't exist
        """
        file_path = self.get_file_path(filename, permanent=permanent)
        try:
            return os.path.getsize(file_path)
        except FileNotFoundError:
            return None
    
    def change_upload_directory(self, new_directory: str) -> Tuple[bool, Optional[str]]:
        """
        Change the upload directory.
        
        Args:
            new_directory: New upload directory path
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            self._ensure_directory_exists(new_directory)
            self.upload_directory = new_directory
            return True, None
        except Exception as e:
            return False, str(e)
    
    def get_upload_directory(self) -> str:
        """Get current upload directory."""
        return self.upload_directory


# Global file manager instance
file_manager = FileManager()


def get_file_manager() -> FileManager:
    """Get the global file manager instance."""
    return file_manager


def set_upload_directory(directory: str) -> Tuple[bool, Optional[str]]:
    """
    Set the upload directory globally.
    
    Args:
        directory: New upload directory path
        
    Returns:
        Tuple of (success, error_message)
    """
    return file_manager.change_upload_directory(directory)
