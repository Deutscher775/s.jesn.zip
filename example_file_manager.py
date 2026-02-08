"""
Example script demonstrating how to use the FileManager
and change the upload directory dynamically.
"""

from file_manager import get_file_manager, set_upload_directory
import os


def example_basic_usage():
    """Example: Basic FileManager usage"""
    print("=== Basic FileManager Usage ===\n")
    
    # Get the global file manager instance
    fm = get_file_manager()
    
    # Get current upload directory
    print(f"Current upload directory: {fm.get_upload_directory()}")
    
    # Get file paths
    regular_file_path = fm.get_file_path("example.txt")
    permanent_file_path = fm.get_file_path("example.txt", permanent=True)
    
    print(f"Regular file path: {regular_file_path}")
    print(f"Permanent file path: {permanent_file_path}")
    
    # Get conversion paths
    conversion_input = fm.get_conversion_input_path("video.mp4")
    conversion_output = fm.get_conversion_output_path("video", "avi", permanent=False)
    
    print(f"Conversion input path: {conversion_input}")
    print(f"Conversion output path: {conversion_output}")
    print()


def example_change_directory():
    """Example: Change upload directory"""
    print("=== Changing Upload Directory ===\n")
    
    # Change to a different directory
    new_directory = "./test_uploads"
    
    success, error = set_upload_directory(new_directory)
    
    if success:
        print(f"✓ Successfully changed upload directory to: {new_directory}")
        
        # Verify the change
        fm = get_file_manager()
        print(f"✓ Current directory: {fm.get_upload_directory()}")
        
        # The directory is automatically created
        print(f"✓ Directory exists: {os.path.exists(new_directory)}")
    else:
        print(f"✗ Failed to change directory: {error}")
    
    print()


def example_file_validation():
    """Example: Validate filenames"""
    print("=== Filename Validation ===\n")
    
    fm = get_file_manager()
    
    test_filenames = [
        "normal_file.txt",
        "PERM_file.txt",  # Should fail without allow_permanent_prefix
        "../etc/passwd",  # Path traversal attempt
        "valid/path.txt",  # Contains slash
        "",  # Empty filename
    ]
    
    for filename in test_filenames:
        is_valid, error = fm.validate_filename(filename, allow_permanent_prefix=False)
        status = "✓" if is_valid else "✗"
        message = "Valid" if is_valid else f"Invalid: {error}"
        print(f"{status} '{filename}' - {message}")
    
    print()


def example_list_files():
    """Example: List files in upload directory"""
    print("=== List Files ===\n")
    
    fm = get_file_manager()
    
    # List all files (excluding conversion inputs)
    all_files = fm.list_files()
    print(f"All files ({len(all_files)}):")
    for filename in all_files[:5]:  # Show first 5
        print(f"  - {filename}")
    
    # List only permanent files
    permanent_files = fm.list_files(permanent_only=True)
    print(f"\nPermanent files ({len(permanent_files)}):")
    for filename in permanent_files[:5]:  # Show first 5
        print(f"  - {filename}")
    
    print()


def example_file_operations():
    """Example: File operations"""
    print("=== File Operations ===\n")
    
    fm = get_file_manager()
    
    test_file = "test_example.txt"
    
    # Check if file exists
    exists = fm.file_exists(test_file)
    print(f"File '{test_file}' exists: {exists}")
    
    # Create a test file
    if not exists:
        file_path = fm.get_file_path(test_file)
        with open(file_path, "w") as f:
            f.write("This is a test file.")
        print(f"✓ Created test file: {file_path}")
    
    # Get file size
    size = fm.get_file_size(test_file)
    print(f"File size: {size} bytes")
    
    # Check if it's a permanent file
    is_perm = fm.is_permanent_file(test_file)
    print(f"Is permanent: {is_perm}")
    
    # Delete the test file
    success, error = fm.delete_file(test_file)
    if success:
        print(f"✓ Deleted test file")
    else:
        print(f"✗ Failed to delete: {error}")
    
    print()


def example_api_usage():
    """Example: How to use with API endpoints"""
    print("=== API Usage Example ===\n")
    
    print("To change upload directory via API:")
    print("POST /api/config/upload-directory")
    print('{"directory": "/new/upload/path"}')
    print()
    
    print("To get current upload directory:")
    print("GET /api/config/upload-directory")
    print()
    
    print("To list files:")
    print("GET /api/files/list")
    print("GET /api/files/list?permanent_only=true")
    print()


if __name__ == "__main__":
    print("FileManager Examples\n" + "=" * 50 + "\n")
    
    # Run examples
    example_basic_usage()
    example_file_validation()
    
    # Uncomment to test changing directory
    # example_change_directory()
    
    # Uncomment to test listing files (requires existing files)
    # example_list_files()
    
    # Uncomment to test file operations
    # example_file_operations()
    
    example_api_usage()
    
    print("=" * 50)
    print("\nNote: Some examples are commented out to avoid")
    print("modifying your actual upload directory.")
