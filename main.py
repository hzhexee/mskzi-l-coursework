import sys
import os
import binascii
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QRadioButton, QButtonGroup, QLabel, QTextEdit,
                             QFileDialog, QTabWidget, QLineEdit, QMessageBox, QGroupBox,
                             QSplitter, QCheckBox)
from PyQt6.QtCore import Qt, QBuffer, QIODevice
from PyQt6.QtGui import QIcon

from chacha20 import (chacha20_encrypt, chacha20_decrypt, generate_key,
                      encrypt_file, decrypt_file)


class ChaCha20App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.key = None
        self.salt = None
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('ChaCha20 Шифрование')
        self.setGeometry(100, 100, 800, 600)
        
        # Создаем центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Верхняя панель с переключателем режима
        mode_group = QGroupBox("Режим")
        mode_layout = QHBoxLayout()
        
        self.encrypt_radio = QRadioButton("Шифрование")
        self.decrypt_radio = QRadioButton("Дешифрование")
        self.encrypt_radio.setChecked(True)
        
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.encrypt_radio, 1)
        self.mode_group.addButton(self.decrypt_radio, 2)
        
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        mode_group.setLayout(mode_layout)
        
        main_layout.addWidget(mode_group)
        
        # Панель выбора типа данных
        data_type_group = QGroupBox("Тип данных")
        data_type_layout = QHBoxLayout()
        
        self.text_button = QPushButton("Текст")
        self.file_button = QPushButton("Файл")
        
        data_type_layout.addWidget(self.text_button)
        data_type_layout.addWidget(self.file_button)
        data_type_group.setLayout(data_type_layout)
        
        main_layout.addWidget(data_type_group)
        
        # Основная часть интерфейса с вкладками
        self.tabs = QTabWidget()
        self.text_tab = QWidget()
        self.file_tab = QWidget()
        
        self.tabs.addTab(self.text_tab, "Текст")
        self.tabs.addTab(self.file_tab, "Файл")
        
        main_layout.addWidget(self.tabs)
        
        # Настройка вкладки текста
        self.setup_text_tab()
        
        # Настройка вкладки файла
        self.setup_file_tab()
        
        # Подключаем сигналы к слотам
        self.text_button.clicked.connect(lambda: self.tabs.setCurrentIndex(0))
        self.file_button.clicked.connect(lambda: self.tabs.setCurrentIndex(1))
        self.encrypt_radio.toggled.connect(self.update_ui_state)
        
        # Начальное обновление состояния интерфейса
        self.update_ui_state()
        
    def setup_text_tab(self):
        layout = QVBoxLayout(self.text_tab)
        
        # Поля ввода/вывода текста
        input_group = QGroupBox("Исходный текст")
        input_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        input_layout.addWidget(self.text_input)
        input_group.setLayout(input_layout)
        
        output_group = QGroupBox("Результат")
        output_layout = QVBoxLayout()
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        output_layout.addWidget(self.text_output)
        output_group.setLayout(output_layout)
        
        # Панель управления ключом
        key_group = QGroupBox("Управление ключом")
        key_layout = QVBoxLayout()
        
        key_input_layout = QHBoxLayout()
        key_input_layout.addWidget(QLabel("Ключ (hex):"))
        self.key_input = QLineEdit()
        key_input_layout.addWidget(self.key_input)
        
        key_buttons_layout = QHBoxLayout()
        self.generate_key_button = QPushButton("Сгенерировать ключ")
        self.copy_key_button = QPushButton("Копировать ключ")
        key_buttons_layout.addWidget(self.generate_key_button)
        key_buttons_layout.addWidget(self.copy_key_button)
        
        key_layout.addLayout(key_input_layout)
        key_layout.addLayout(key_buttons_layout)
        key_group.setLayout(key_layout)
        
        # Кнопка обработки
        self.process_text_button = QPushButton("Обработать")
        
        # Размещение элементов
        input_output_splitter = QSplitter(Qt.Orientation.Vertical)
        input_output_splitter.addWidget(input_group)
        input_output_splitter.addWidget(output_group)
        
        layout.addWidget(input_output_splitter)
        layout.addWidget(key_group)
        layout.addWidget(self.process_text_button)
        
        # Подключаем сигналы
        self.generate_key_button.clicked.connect(self.generate_new_key)
        self.copy_key_button.clicked.connect(self.copy_key_to_clipboard)
        self.process_text_button.clicked.connect(self.process_text)
        
    def setup_file_tab(self):
        layout = QVBoxLayout(self.file_tab)
        
        # Выбор входного файла
        input_file_group = QGroupBox("Входной файл")
        input_file_layout = QHBoxLayout()
        self.input_file_path = QLineEdit()
        self.input_file_path.setReadOnly(True)
        self.browse_input_button = QPushButton("Обзор...")
        input_file_layout.addWidget(self.input_file_path)
        input_file_layout.addWidget(self.browse_input_button)
        input_file_group.setLayout(input_file_layout)
        
        # Выбор выходного файла
        output_file_group = QGroupBox("Выходной файл")
        output_file_layout = QHBoxLayout()
        self.output_file_path = QLineEdit()
        self.output_file_path.setReadOnly(True)
        self.browse_output_button = QPushButton("Обзор...")
        output_file_layout.addWidget(self.output_file_path)
        output_file_layout.addWidget(self.browse_output_button)
        output_file_group.setLayout(output_file_layout)
        
        # Панель управления ключом (аналогично вкладке текста)
        key_group = QGroupBox("Управление ключом")
        key_layout = QVBoxLayout()
        
        key_input_layout = QHBoxLayout()
        key_input_layout.addWidget(QLabel("Ключ (hex):"))
        self.file_key_input = QLineEdit()
        key_input_layout.addWidget(self.file_key_input)
        
        key_buttons_layout = QHBoxLayout()
        self.generate_file_key_button = QPushButton("Сгенерировать ключ")
        self.copy_file_key_button = QPushButton("Копировать ключ")
        key_buttons_layout.addWidget(self.generate_file_key_button)
        key_buttons_layout.addWidget(self.copy_file_key_button)
        
        key_layout.addLayout(key_input_layout)
        key_layout.addLayout(key_buttons_layout)
        key_group.setLayout(key_layout)
        
        # Кнопка обработки файла
        self.process_file_button = QPushButton("Обработать файл")
        
        # Размещение элементов
        layout.addWidget(input_file_group)
        layout.addWidget(output_file_group)
        layout.addWidget(key_group)
        layout.addWidget(self.process_file_button)
        
        # Подключаем сигналы
        self.browse_input_button.clicked.connect(self.browse_input_file)
        self.browse_output_button.clicked.connect(self.browse_output_file)
        self.generate_file_key_button.clicked.connect(self.generate_new_file_key)
        self.copy_file_key_button.clicked.connect(self.copy_file_key_to_clipboard)
        self.process_file_button.clicked.connect(self.process_file)
        
    def update_ui_state(self):
        is_encrypt = self.encrypt_radio.isChecked()
        
        # Обновляем текст на кнопках и подсказках в зависимости от режима
        if is_encrypt:
            self.process_text_button.setText("Зашифровать")
            self.process_file_button.setText("Зашифровать файл")
        else:
            self.process_text_button.setText("Дешифровать")
            self.process_file_button.setText("Дешифровать файл")
            
    def generate_new_key(self):
        self.key, self.salt = generate_key()
        self.key_input.setText(self.key.hex())
        
    def generate_new_file_key(self):
        self.key, self.salt = generate_key()
        self.file_key_input.setText(self.key.hex())
        
    def copy_key_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.key_input.text())
        QMessageBox.information(self, "Копирование", "Ключ скопирован в буфер обмена")
        
    def copy_file_key_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.file_key_input.text())
        QMessageBox.information(self, "Копирование", "Ключ скопирован в буфер обмена")
        
    def browse_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл", "", "Все файлы (*)"
        )
        
        if file_path:
            self.input_file_path.setText(file_path)
            
            # Автоматически предлагаем имя выходного файла
            if self.encrypt_radio.isChecked():
                output_path = file_path + ".encrypted"
            else:
                if file_path.endswith(".encrypted"):
                    output_path = file_path[:-10]  # Убираем расширение .encrypted
                else:
                    output_path = file_path + ".decrypted"
                    
            self.output_file_path.setText(output_path)
            
    def browse_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить как", "", "Все файлы (*)"
        )
        
        if file_path:
            self.output_file_path.setText(file_path)
            
    def process_text(self):
        input_text = self.text_input.toPlainText()
        
        # Проверяем наличие ключа
        key_hex = self.key_input.text()
        if not key_hex:
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, введите или сгенерируйте ключ")
            return
            
        try:
            # Преобразуем ключ из hex в bytes
            key = bytes.fromhex(key_hex)
            
            if self.encrypt_radio.isChecked():
                # Шифрование
                result = chacha20_encrypt(input_text.encode('utf-8'), key)
                # Отображаем результат в виде hex строки
                self.text_output.setText(result.hex())
            else:
                # Дешифрование - ожидаем hex строку на входе
                try:
                    binary_data = bytes.fromhex(input_text)
                    result = chacha20_decrypt(binary_data, key)
                    # Пытаемся декодировать как текст
                    self.text_output.setText(result.decode('utf-8'))
                except ValueError:
                    QMessageBox.warning(self, "Ошибка", "Неверный формат входных данных. Ожидается hex строка.")
                except UnicodeDecodeError:
                    QMessageBox.warning(self, "Ошибка", "Не удалось декодировать результат как текст.")
                    
        except ValueError as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка обработки: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Непредвиденная ошибка: {str(e)}")
            
    def process_file(self):
        input_path = self.input_file_path.text()
        output_path = self.output_file_path.text()
        
        if not input_path or not output_path:
            QMessageBox.warning(self, "Ошибка", "Выберите входной и выходной файлы")
            return
            
        # Проверяем наличие ключа
        key_hex = self.file_key_input.text()
        if not key_hex:
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, введите или сгенерируйте ключ")
            return
            
        try:
            # Преобразуем ключ из hex в bytes
            key = bytes.fromhex(key_hex)
            
            if self.encrypt_radio.isChecked():
                # Шифрование файла
                try:
                    key, salt = encrypt_file(input_path, output_path, key)
                    QMessageBox.information(self, "Успех", 
                                          f"Файл успешно зашифрован и сохранен в:\n{output_path}")
                    
                    # Обновляем ключ в интерфейсе, так как он может быть изменен
                    self.file_key_input.setText(key.hex())
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Ошибка шифрования файла: {str(e)}")
            else:
                # Дешифрование файла
                try:
                    success = decrypt_file(input_path, output_path, key)
                    if success:
                        QMessageBox.information(self, "Успех", 
                                               f"Файл успешно дешифрован и сохранен в:\n{output_path}")
                    else:
                        QMessageBox.warning(self, "Ошибка", "Не удалось дешифровать файл. Возможно, неверный ключ.")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Ошибка дешифрования файла: {str(e)}")
                    
        except ValueError as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка обработки: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Непредвиденная ошибка: {str(e)}")


def main():
    app = QApplication(sys.argv)
    window = ChaCha20App()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
