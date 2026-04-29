import argparse
import json
import uuid
from datetime import datetime, timezone

from smbprotocol import Dialects
from smbprotocol.connection import Connection
from smbprotocol.file_info import (
    FileAttributes,
    FileBasicInformation,
    FileDispositionInformation,
    FileEndOfFileInformation,
    FileInformationClass,
    FileRenameInformation,
    FileStandardInformation,
    InfoType,
    QueryInfoFlags,
)
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    SMB2QueryInfoRequest,
    SMB2QueryInfoResponse,
    SMB2SetInfoRequest,
    SMB2SetInfoResponse,
    ShareAccess,
)
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

DELETE_ACCESS = 0x00010000
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
SINGLE_CREDIT_CHUNK = 65536


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a real SMB client smoke test against Sample.OpenCifsServer.")
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--share", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--domain", default="")
    parser.add_argument("--directory", default="real-client-smoke")
    parser.add_argument("--file", default="smoke.txt")
    parser.add_argument("--payload", default="hello from smbprotocol")
    parser.add_argument("--large-payload-length", type=int, default=200000)
    return parser.parse_args()


def decode_file_name(entry) -> str:
    raw_name = entry["file_name"].get_value()

    if isinstance(raw_name, bytes):
        return raw_name.decode("utf-16-le")

    return str(raw_name)


def to_filetime_utc(value: datetime) -> int:
    utc_value = value.astimezone(timezone.utc)
    delta = utc_value - FILETIME_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def create_large_payload(length: int) -> bytes:
    if length <= 0:
        raise ValueError("large payload length must be positive")

    return bytes((ord("A") + (index % 23)) for index in range(length))


def query_file_information(open_handle: Open, information_class: int, information_structure):
    request = SMB2QueryInfoRequest()
    request["info_type"] = InfoType.SMB2_0_INFO_FILE
    request["file_info_class"] = information_class
    request["output_buffer_length"] = 65536
    request["additional_information"] = 0
    request["flags"] = QueryInfoFlags.NONE
    request["file_id"] = open_handle.file_id
    request["buffer"] = b""

    response = open_handle.connection.receive(
        open_handle.connection.send(
            request,
            open_handle.tree_connect.session.session_id,
            open_handle.tree_connect.tree_connect_id,
        )
    )
    query_response = SMB2QueryInfoResponse()
    query_response.unpack(response["data"].get_value())

    information = information_structure()
    information.unpack(query_response["buffer"].get_value())
    return information


def set_file_information(open_handle: Open, information) -> None:
    request = SMB2SetInfoRequest()
    request["info_type"] = information.INFO_TYPE
    request["file_info_class"] = information.INFO_CLASS
    request["additional_information"] = 0
    request["file_id"] = open_handle.file_id
    request["buffer"] = information.pack()

    response = open_handle.connection.receive(
        open_handle.connection.send(
            request,
            open_handle.tree_connect.session.session_id,
            open_handle.tree_connect.tree_connect_id,
        )
    )
    set_response = SMB2SetInfoResponse()
    set_response.unpack(response["data"].get_value())


def write_bytes_in_chunks(open_handle: Open, payload: bytes, chunk_size: int = SINGLE_CREDIT_CHUNK) -> int:
    total_written = 0

    for offset in range(0, len(payload), chunk_size):
        chunk = payload[offset:offset + chunk_size]
        total_written += open_handle.write(chunk, offset=offset)

    return total_written


def read_bytes_in_chunks(open_handle: Open, length: int, chunk_size: int = SINGLE_CREDIT_CHUNK) -> bytes:
    chunks = []

    for offset in range(0, length, chunk_size):
        current_length = min(chunk_size, length - offset)
        chunks.append(open_handle.read(offset, current_length))

    return b"".join(chunks)


def main() -> int:
    args = parse_args()
    combined_username = args.username if not args.domain else args.domain + "\\" + args.username
    payload = args.payload.encode("utf-8")
    large_payload = create_large_payload(args.large_payload_length)
    truncated_payload = payload[:6]
    file_path = args.directory + "\\" + args.file
    large_file = "large.bin"
    large_file_path = args.directory + "\\" + large_file
    renamed_file = "renamed-" + args.file
    renamed_file_path = args.directory + "\\" + renamed_file
    nested_directory = args.directory + "\\nested"
    renamed_directory = args.directory + "-renamed"
    renamed_nested_directory = renamed_directory + "\\nested"
    share_path = "\\\\" + args.server + "\\" + args.share
    expected_last_write_utc = datetime(2024, 5, 6, 7, 8, 9, tzinfo=timezone.utc)
    expected_last_write_filetime = to_filetime_utc(expected_last_write_utc)

    connection = Connection(uuid.uuid4(), args.server, args.port, require_signing=True)
    session = None
    tree = None
    directory_open = None
    nested_directory_open = None
    delete_attempt_directory_open = None
    file_open = None
    large_file_open = None
    query_open = None
    renamed_file_open = None
    renamed_directory_open = None

    try:
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(
            connection,
            username=combined_username,
            password=args.password,
            require_encryption=False,
            auth_protocol="ntlm")
        session.connect()

        tree = TreeConnect(session, share_path)
        tree.connect(require_secure_negotiate=False)

        directory_open = Open(tree, args.directory)
        directory_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=DirectoryAccessMask.GENERIC_ALL | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN_IF,
            create_options=CreateOptions.FILE_DIRECTORY_FILE)
        directory_open.close()
        directory_open = None

        nested_directory_open = Open(tree, nested_directory)
        nested_directory_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=DirectoryAccessMask.GENERIC_ALL | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN_IF,
            create_options=CreateOptions.FILE_DIRECTORY_FILE)
        nested_directory_open.close()
        nested_directory_open = None

        file_open = Open(tree, file_path)
        file_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN_IF,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        bytes_written = file_open.write(payload, offset=0)
        file_open.flush()
        bytes_read = file_open.read(0, len(payload))
        standard_information = query_file_information(
            file_open,
            FileInformationClass.FILE_STANDARD_INFORMATION,
            FileStandardInformation,
        )

        basic_information = FileBasicInformation()
        basic_information["last_write_time"] = expected_last_write_filetime
        basic_information["file_attributes"] = FileAttributes.FILE_ATTRIBUTE_HIDDEN
        set_file_information(file_open, basic_information)
        updated_basic_information = query_file_information(
            file_open,
            FileInformationClass.FILE_BASIC_INFORMATION,
            FileBasicInformation,
        )

        end_of_file_information = FileEndOfFileInformation()
        end_of_file_information["end_of_file"] = len(truncated_payload)
        set_file_information(file_open, end_of_file_information)
        truncated_standard_information = query_file_information(
            file_open,
            FileInformationClass.FILE_STANDARD_INFORMATION,
            FileStandardInformation,
        )
        truncated_bytes_read = file_open.read(0, len(truncated_payload))

        large_file_open = Open(tree, large_file_path)
        large_file_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN_IF,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        large_bytes_written = write_bytes_in_chunks(large_file_open, large_payload)
        large_file_open.flush()
        large_bytes_read = read_bytes_in_chunks(large_file_open, len(large_payload))
        large_standard_information = query_file_information(
            large_file_open,
            FileInformationClass.FILE_STANDARD_INFORMATION,
            FileStandardInformation,
        )

        if large_bytes_written != len(large_payload):
            raise RuntimeError("The SMB client wrote an unexpected bounded large-I/O byte count.")

        if large_bytes_read != large_payload:
            raise RuntimeError("The SMB client read back unexpected bounded large-I/O contents.")

        if large_standard_information["end_of_file"].get_value() != len(large_payload):
            raise RuntimeError("The SMB client metadata query returned an unexpected bounded large-I/O end-of-file size.")

        disposition_information = FileDispositionInformation()
        disposition_information["delete_pending"] = True
        set_file_information(large_file_open, disposition_information)
        large_file_open.close()
        large_file_open = None

        rename_information = FileRenameInformation()
        rename_information["replace_if_exists"] = False
        rename_information["root_directory"] = 0
        rename_information["file_name"] = renamed_file_path
        set_file_information(file_open, rename_information)
        file_open.close()
        file_open = None

        renamed_file_open = Open(tree, renamed_file_path)
        renamed_file_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE)
        renamed_bytes_read = renamed_file_open.read(0, len(truncated_payload))

        query_open = Open(tree, args.directory)
        query_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=DirectoryAccessMask.GENERIC_READ,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_DIRECTORY_FILE)
        renamed_directory_entries = query_open.query_directory("*", FileInformationClass.FILE_FULL_DIRECTORY_INFORMATION)
        query_open.close()
        query_open = None

        non_empty_directory_delete_rejected = False
        delete_attempt_directory_open = Open(tree, args.directory)
        delete_attempt_directory_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=DirectoryAccessMask.GENERIC_ALL | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_DIRECTORY_FILE)
        try:
            disposition_information = FileDispositionInformation()
            disposition_information["delete_pending"] = True
            set_file_information(delete_attempt_directory_open, disposition_information)
        except Exception:
            non_empty_directory_delete_rejected = True

        if not non_empty_directory_delete_rejected:
            raise RuntimeError("The SMB client unexpectedly deleted or marked a non-empty directory delete-pending.")

        delete_attempt_directory_open.close()
        delete_attempt_directory_open = None

        readonly_basic_information = FileBasicInformation()
        readonly_basic_information["file_attributes"] = FileAttributes.FILE_ATTRIBUTE_READONLY
        set_file_information(renamed_file_open, readonly_basic_information)
        readonly_basic_information_after_update = query_file_information(
            renamed_file_open,
            FileInformationClass.FILE_BASIC_INFORMATION,
            FileBasicInformation,
        )
        read_only_delete_rejected = False

        try:
            disposition_information = FileDispositionInformation()
            disposition_information["delete_pending"] = True
            set_file_information(renamed_file_open, disposition_information)
        except Exception:
            read_only_delete_rejected = True

        if not read_only_delete_rejected:
            raise RuntimeError("The SMB client unexpectedly deleted or marked a read-only file delete-pending.")

        standard_information_after_failed_delete = query_file_information(
            renamed_file_open,
            FileInformationClass.FILE_STANDARD_INFORMATION,
            FileStandardInformation,
        )
        clear_readonly_basic_information = FileBasicInformation()
        clear_readonly_basic_information["file_attributes"] = FileAttributes.FILE_ATTRIBUTE_NORMAL
        set_file_information(renamed_file_open, clear_readonly_basic_information)

        disposition_information = FileDispositionInformation()
        disposition_information["delete_pending"] = True
        set_file_information(renamed_file_open, disposition_information)
        renamed_file_open.close()
        renamed_file_open = None

        nested_directory_open = Open(tree, nested_directory)
        nested_directory_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=DirectoryAccessMask.GENERIC_ALL | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_DIRECTORY_FILE)
        disposition_information = FileDispositionInformation()
        disposition_information["delete_pending"] = True
        set_file_information(nested_directory_open, disposition_information)
        nested_directory_open.close()
        nested_directory_open = None

        directory_open = Open(tree, args.directory)
        directory_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=DirectoryAccessMask.GENERIC_ALL | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_DIRECTORY_FILE)
        directory_rename_information = FileRenameInformation()
        directory_rename_information["replace_if_exists"] = False
        directory_rename_information["root_directory"] = 0
        directory_rename_information["file_name"] = renamed_directory
        set_file_information(directory_open, directory_rename_information)
        directory_open.close()
        directory_open = None

        renamed_directory_open = Open(tree, renamed_directory)
        renamed_directory_open.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=DirectoryAccessMask.GENERIC_ALL | DELETE_ACCESS,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_DIRECTORY_FILE)
        disposition_information = FileDispositionInformation()
        disposition_information["delete_pending"] = True
        set_file_information(renamed_directory_open, disposition_information)
        renamed_directory_open.close()
        renamed_directory_open = None

        decoded_renamed_names = [decode_file_name(entry) for entry in renamed_directory_entries]

        if bytes_written != len(payload):
            raise RuntimeError("The SMB client wrote an unexpected byte count.")

        if bytes_read != payload:
            raise RuntimeError("The SMB client read back unexpected file contents.")

        if standard_information["end_of_file"].get_value() != len(payload):
            raise RuntimeError("The SMB client metadata query returned an unexpected end-of-file size.")

        if not updated_basic_information["file_attributes"].has_flag(FileAttributes.FILE_ATTRIBUTE_HIDDEN):
            raise RuntimeError("The SMB client basic-info mutation did not preserve the Hidden attribute.")

        if updated_basic_information["last_write_time"].get_value() != expected_last_write_filetime:
            raise RuntimeError("The SMB client basic-info mutation did not preserve the requested last-write time.")

        if truncated_standard_information["end_of_file"].get_value() != len(truncated_payload):
            raise RuntimeError("The SMB client end-of-file mutation returned an unexpected truncated size.")

        if truncated_bytes_read != truncated_payload:
            raise RuntimeError("The SMB client read back unexpected file contents after truncating the file.")

        if renamed_bytes_read != truncated_payload:
            raise RuntimeError("The SMB client read back unexpected file contents after renaming the truncated file.")

        if renamed_file not in decoded_renamed_names:
            raise RuntimeError("The SMB client directory enumeration did not return the renamed file.")

        if "nested" not in decoded_renamed_names:
            raise RuntimeError("The SMB client directory enumeration did not return the nested directory.")

        if not readonly_basic_information_after_update["file_attributes"].has_flag(FileAttributes.FILE_ATTRIBUTE_READONLY):
            raise RuntimeError("The SMB client basic-info mutation did not preserve the ReadOnly attribute.")

        if standard_information_after_failed_delete["delete_pending"].get_value():
            raise RuntimeError("The SMB client left the read-only file delete-pending after the expected failure.")

        summary = {
            "server": args.server,
            "port": args.port,
            "share": args.share,
            "dialect": "SMB 2.1",
            "directory": args.directory,
            "nested_directory": nested_directory,
            "file": args.file,
            "large_file": large_file,
            "renamed_file": renamed_file,
            "renamed_directory": renamed_directory,
            "bytes_written": bytes_written,
            "large_payload_length": len(large_payload),
            "large_bytes_written": large_bytes_written,
            "large_end_of_file": large_standard_information["end_of_file"].get_value(),
            "initial_end_of_file": standard_information["end_of_file"].get_value(),
            "mutated_last_write_time": updated_basic_information["last_write_time"].get_value(),
            "hidden_attribute_set": updated_basic_information["file_attributes"].has_flag(FileAttributes.FILE_ATTRIBUTE_HIDDEN),
            "readonly_attribute_set": readonly_basic_information_after_update["file_attributes"].has_flag(FileAttributes.FILE_ATTRIBUTE_READONLY),
            "read_only_delete_rejected": read_only_delete_rejected,
            "non_empty_directory_delete_rejected": non_empty_directory_delete_rejected,
            "delete_pending_after_failed_readonly_delete": standard_information_after_failed_delete["delete_pending"].get_value(),
            "end_of_file": truncated_standard_information["end_of_file"].get_value(),
            "directory_entries_after_file_rename": decoded_renamed_names,
            "renamed_directory_opened": True,
            "renamed_nested_directory_deleted": True,
        }
        print(json.dumps(summary, indent=2))
        return 0

    finally:
        if delete_attempt_directory_open is not None:
            try:
                delete_attempt_directory_open.close()
            except Exception:
                pass

        if nested_directory_open is not None:
            try:
                nested_directory_open.close()
            except Exception:
                pass

        if renamed_directory_open is not None:
            try:
                renamed_directory_open.close()
            except Exception:
                pass

        if renamed_file_open is not None:
            try:
                renamed_file_open.close()
            except Exception:
                pass

        if query_open is not None:
            try:
                query_open.close()
            except Exception:
                pass

        if file_open is not None:
            try:
                file_open.close()
            except Exception:
                pass

        if large_file_open is not None:
            try:
                large_file_open.close()
            except Exception:
                pass

        if directory_open is not None:
            try:
                directory_open.close()
            except Exception:
                pass

        if tree is not None:
            try:
                tree.disconnect()
            except Exception:
                pass

        if session is not None:
            try:
                session.disconnect()
            except Exception:
                pass

        try:
            connection.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
