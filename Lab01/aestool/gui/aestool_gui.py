from __future__ import annotations

import ctypes
import platform
import sys
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


ROOT = Path(__file__).resolve().parents[1]


def default_library_candidates() -> list[Path]:
    system = platform.system().lower()
    if system == "windows":
        names = ["aestool_core.dll"]
        dirs = [
            ROOT / "build-cmake-4.3.3" / "Release",
            ROOT / "build" / "Release",
            ROOT / "build",
        ]
    elif system == "darwin":
        names = ["libaestool_core.dylib"]
        dirs = [ROOT / "build-cmake-4.3.3", ROOT / "build"]
    else:
        names = ["libaestool_core.so"]
        dirs = [ROOT / "build-cmake-4.3.3", ROOT / "build"]
    return [directory / name for directory in dirs for name in names]


class AesToolCore:
    def __init__(self, path: Path):
        self.path = path
        self.lib = ctypes.CDLL(str(path))
        c_char_p = ctypes.c_char_p
        c_int = ctypes.c_int
        c_size_t = ctypes.c_size_t

        self.lib.aestool_core_keygen.argtypes = [c_char_p, c_int, c_char_p, c_size_t]
        self.lib.aestool_core_keygen.restype = c_int

        self.lib.aestool_core_encrypt_file.argtypes = [
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_size_t,
        ]
        self.lib.aestool_core_encrypt_file.restype = c_int

        self.lib.aestool_core_encrypt_text.argtypes = [
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_size_t,
        ]
        self.lib.aestool_core_encrypt_text.restype = c_int

        self.lib.aestool_core_decrypt_file.argtypes = [
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_char_p,
            c_size_t,
        ]
        self.lib.aestool_core_decrypt_file.restype = c_int

    @staticmethod
    def _b(value: str) -> bytes:
        return value.encode("utf-8")

    def _call(self, fn, *args) -> str:
        error = ctypes.create_string_buffer(2048)
        rc = fn(*args, error, ctypes.sizeof(error))
        message = error.value.decode("utf-8", errors="replace")
        if rc != 0:
            raise RuntimeError(message)
        return message

    def keygen(self, out_file: str, bits: int) -> str:
        return self._call(self.lib.aestool_core_keygen, self._b(out_file), bits)

    def encrypt_file(self, mode: str, key_file: str, input_file: str, output_file: str, aad: str) -> str:
        return self._call(
            self.lib.aestool_core_encrypt_file,
            self._b(mode),
            self._b(key_file),
            self._b(input_file),
            self._b(output_file),
            self._b(aad),
        )

    def encrypt_text(self, mode: str, key_file: str, text: str, output_file: str, aad: str) -> str:
        return self._call(
            self.lib.aestool_core_encrypt_text,
            self._b(mode),
            self._b(key_file),
            self._b(text),
            self._b(output_file),
            self._b(aad),
        )

    def decrypt_file(self, mode: str, key_file: str, input_file: str, output_file: str) -> str:
        return self._call(
            self.lib.aestool_core_decrypt_file,
            self._b(mode),
            self._b(key_file),
            self._b(input_file),
            self._b(output_file),
        )


class PathRow(QWidget):
    def __init__(self, mode: str = "open", file_filter: str = "All files (*)"):
        super().__init__()
        self.mode = mode
        self.file_filter = file_filter
        self.edit = QLineEdit()
        self.button = QPushButton("Browse")
        self.button.clicked.connect(self.choose)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.edit, 1)
        layout.addWidget(self.button)

    def choose(self):
        if self.mode == "save":
            path, _ = QFileDialog.getSaveFileName(self, "Choose file", "", self.file_filter)
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Choose file", "", self.file_filter)
        if path:
            self.edit.setText(path)

    def text(self) -> str:
        return self.edit.text().strip()

    def set_text(self, value: str):
        self.edit.setText(value)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES Tool - Lab 1 Bonus GUI")
        self.resize(780, 620)
        self.core: AesToolCore | None = None

        central = QWidget()
        layout = QVBoxLayout(central)

        self.lib_path = PathRow("open", "Shared library (*.dll *.so *.dylib);;All files (*)")
        for candidate in default_library_candidates():
            if candidate.exists():
                self.lib_path.set_text(str(candidate))
                break
        load_button = QPushButton("Load Core")
        load_button.clicked.connect(self.load_core)
        lib_layout = QHBoxLayout()
        lib_layout.addWidget(self.lib_path, 1)
        lib_layout.addWidget(load_button)

        lib_box = QGroupBox("Compiled C++ Core Library")
        lib_box.setLayout(lib_layout)
        layout.addWidget(lib_box)

        self.status = QLabel("Core not loaded")
        self.status.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.status)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.make_keygen_tab(), "Keygen")
        self.tabs.addTab(self.make_encrypt_tab(), "Encrypt")
        self.tabs.addTab(self.make_decrypt_tab(), "Decrypt")
        layout.addWidget(self.tabs, 1)

        self.setCentralWidget(central)
        if self.lib_path.text():
            self.load_core()

    def make_mode_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItems(["gcm", "ccm", "ctr", "cbc", "cfb", "ofb", "xts", "ecb"])
        return combo

    def make_keygen_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        self.keygen_bits = QComboBox()
        self.keygen_bits.addItems(["128", "192", "256", "512"])
        self.keygen_bits.setCurrentText("256")
        self.keygen_out = PathRow("save", "Key files (*.bin);;All files (*)")
        button = QPushButton("Generate Key")
        button.clicked.connect(self.keygen)
        form.addRow("Bits", self.keygen_bits)
        form.addRow("Output key", self.keygen_out)
        form.addRow(button)
        return widget

    def make_encrypt_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        self.enc_mode = self.make_mode_combo()
        self.enc_key = PathRow("open", "Key files (*.bin);;All files (*)")
        self.enc_input = PathRow("open", "All files (*)")
        self.enc_output = PathRow("save", "Ciphertext (*.bin);;All files (*)")
        self.enc_aad = QLineEdit()
        self.enc_text = QPlainTextEdit()
        self.enc_text.setPlaceholderText("Optional text input. If this box is non-empty, it is encrypted instead of the input file.")
        button = QPushButton("Encrypt")
        button.clicked.connect(self.encrypt)
        form.addRow("Mode", self.enc_mode)
        form.addRow("Key", self.enc_key)
        form.addRow("Input file", self.enc_input)
        form.addRow("Text input", self.enc_text)
        form.addRow("Output ciphertext", self.enc_output)
        form.addRow("AAD text", self.enc_aad)
        form.addRow(button)
        return widget

    def make_decrypt_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        self.dec_mode = self.make_mode_combo()
        self.dec_key = PathRow("open", "Key files (*.bin);;All files (*)")
        self.dec_input = PathRow("open", "Ciphertext (*.bin);;All files (*)")
        self.dec_output = PathRow("save", "All files (*)")
        button = QPushButton("Decrypt")
        button.clicked.connect(self.decrypt)
        form.addRow("Mode", self.dec_mode)
        form.addRow("Key", self.dec_key)
        form.addRow("Input ciphertext", self.dec_input)
        form.addRow("Output plaintext", self.dec_output)
        form.addRow(button)
        return widget

    def require_core(self) -> AesToolCore:
        if not self.core:
            raise RuntimeError("Load aestool_core library first")
        return self.core

    def load_core(self):
        try:
            path = Path(self.lib_path.text())
            if not path.exists():
                raise RuntimeError(f"Library not found: {path}")
            self.core = AesToolCore(path)
            self.status.setText(f"Loaded: {path}")
        except Exception as exc:
            self.core = None
            self.status.setText("Core not loaded")
            self.show_error(exc)

    def keygen(self):
        try:
            self.require_core().keygen(self.keygen_out.text(), int(self.keygen_bits.currentText()))
            self.show_info("Key generated")
        except Exception as exc:
            self.show_error(exc)

    def encrypt(self):
        try:
            core = self.require_core()
            mode = self.enc_mode.currentText()
            key = self.enc_key.text()
            output_file = self.enc_output.text()
            aad = self.enc_aad.text()
            text = self.enc_text.toPlainText()
            if text:
                core.encrypt_text(mode, key, text, output_file, aad)
            else:
                core.encrypt_file(mode, key, self.enc_input.text(), output_file, aad)
            self.show_info(f"Encrypted. Metadata written to {output_file}.meta.json")
        except Exception as exc:
            self.show_error(exc)

    def decrypt(self):
        try:
            self.require_core().decrypt_file(
                self.dec_mode.currentText(),
                self.dec_key.text(),
                self.dec_input.text(),
                self.dec_output.text(),
            )
            self.show_info("Decrypted successfully")
        except Exception as exc:
            self.show_error(exc)

    def show_info(self, message: str):
        QMessageBox.information(self, "aestool", message)

    def show_error(self, exc: Exception):
        QMessageBox.critical(self, "aestool error", str(exc))


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
