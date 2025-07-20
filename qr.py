# Thai QR Code Generator & Decoder (Full Tag Support)

import tkinter as tk
from tkinter import ttk, messagebox
import qrcode
from PIL import Image, ImageTk
import crcmod.predefined
import json


def encode_tlv(tag, value):
    return f"{tag}{len(value):02d}{value}"


def parse_tlv(payload):
    result = []
    i = 0
    while i < len(payload):
        tag = payload[i:i+2]
        length = int(payload[i+2:i+4])
        value = payload[i+4:i+4+length]
        raw = payload[i:i+4+length]
        result.append({
            "RawValue": raw,
            "Id": tag,
            "Length": f"{length:02d}",
            "Value": value,
            "IdByConvention": int(tag) if tag.isdigit() else tag
        })
        i += 4 + length
    return result


def calculate_crc(payload):
    crc16 = crcmod.predefined.mkCrcFun('crc-ccitt-false')
    return f"{crc16((payload + '6304').encode('utf-8')):04X}"


def extract_json_model(segments):
    model = {
        "Reusable": any(seg['Id'] == "01" and seg['Value'] == "11" for seg in segments),
        "Currency": "THB",
        "CreditTransfer": None,
        "BillPayment": None,
        "Segments": segments,
        "PayloadFormatIndicator": next((seg['Value'] for seg in segments if seg['Id'] == "00"), None),
        "PointOfInitiationMethod": next((seg['Value'] for seg in segments if seg['Id'] == "01"), None),
        "MerchantAccountInformation": next((seg['Value'] for seg in segments if seg['Id'] == "29"), None),
        "MerchantCategoryCode": next((seg['Value'] for seg in segments if seg['Id'] == "52"), None),
        "TransactionCurrency": next((seg['Value'] for seg in segments if seg['Id'] == "53"), None),
        "TransactionAmount": next((seg['Value'] for seg in segments if seg['Id'] == "54"), None),
        "TipOrConvenienceIndicator": next((seg['Value'] for seg in segments if seg['Id'] == "55"), None),
        "ValueOfConvenienceFeeFixed": next((seg['Value'] for seg in segments if seg['Id'] == "56"), None),
        "ValueOfConvenienceFeePercentage": next((seg['Value'] for seg in segments if seg['Id'] == "57"), None),
        "CountryCode": next((seg['Value'] for seg in segments if seg['Id'] == "58"), None),
        "MerchantName": next((seg['Value'] for seg in segments if seg['Id'] == "59"), None),
        "MerchantCity": next((seg['Value'] for seg in segments if seg['Id'] == "60"), None),
        "PostalCode": next((seg['Value'] for seg in segments if seg['Id'] == "61"), None),
        "AdditionalData": next((seg['Value'] for seg in segments if seg['Id'] == "62"), None),
        "CRC": next((seg['Value'] for seg in segments if seg['Id'] == "63"), None),
        "MerchantInformationLanguageTemplate": next((seg['Value'] for seg in segments if seg['Id'] == "64"), None),
        "RFU": {seg['Id']: seg['Value'] for seg in segments if int(seg['Id']) >= 65 and int(seg['Id']) <= 99}
    }

    for seg in segments:
        if seg['Id'] == "29":
            val = seg['Value']
            ct = {
                "AID": None,
                "MobileNumber": None,
                "NationalIdOrTaxId": None,
                "EWalletId": None,
                "BankAccount": None,
                "OTA": None,
                "CustomerPresentedQR": False
            }
            j = 0
            while j < len(val):
                t = val[j:j+2]
                l = int(val[j+2:j+4])
                v = val[j+4:j+4+l]
                if t == "00":
                    ct["AID"] = v
                    ct["CustomerPresentedQR"] = v.endswith("14")
                elif t == "01": ct["MobileNumber"] = v
                elif t == "02": ct["NationalIdOrTaxId"] = v
                elif t == "03": ct["EWalletId"] = v
                elif t == "04": ct["BankAccount"] = v
                elif t == "05": ct["OTA"] = v
                j += 4 + l
            model["CreditTransfer"] = ct

        elif seg['Id'] == "30":
            val = seg['Value']
            bp = {
                "AID": None,
                "BillerId": None,
                "Ref1": None,
                "Ref2": None
            }
            j = 0
            while j < len(val):
                t = val[j:j+2]
                l = int(val[j+2:j+4])
                v = val[j+4:j+4+l]
                if t == "00": bp["AID"] = v
                elif t == "01": bp["BillerId"] = v
                elif t == "02": bp["Ref1"] = v
                elif t == "03": bp["Ref2"] = v
                j += 4 + l
            model["BillPayment"] = bp

    return model


def build_qr_from_json(json_obj):
    payload = ""
    for seg in json_obj.get("Segments", []):
        if seg["Id"] != "63":  # Skip CRC at this stage
            payload += encode_tlv(seg["Id"], seg["Value"])
    crc = calculate_crc(payload)
    payload += encode_tlv("63", crc)
    return payload


class ThaiQRGUI:
    def __init__(self, root):
        root.title("Thai QR Code Tool - Decode & Generate")

        self.tab = ttk.Notebook(root)
        self.decode_tab = ttk.Frame(self.tab)
        self.generate_tab = ttk.Frame(self.tab)
        self.tab.add(self.decode_tab, text='Decode')
        self.tab.add(self.generate_tab, text='Generate')
        self.tab.pack(expand=1, fill='both')

        # --- Decode Tab ---
        ttk.Label(self.decode_tab, text="Paste QR Payload to Decode:").pack()
        self.qr_input = tk.Text(self.decode_tab, height=5, width=80)
        self.qr_input.pack()
        ttk.Button(self.decode_tab, text="Parse JSON", command=self.decode_qr).pack(pady=5)
        self.output = tk.Text(self.decode_tab, height=30, width=100)
        self.output.pack()

        # --- Generate Tab ---
        ttk.Label(self.generate_tab, text="Paste JSON Payload to Encode:").pack()
        self.json_input = tk.Text(self.generate_tab, height=20, width=100)
        self.json_input.pack()
        ttk.Button(self.generate_tab, text="Generate QR Code", command=self.generate_qr).pack(pady=5)
        self.canvas = tk.Canvas(self.generate_tab, width=300, height=300)
        self.canvas.pack()
        self.raw_output = tk.Text(self.generate_tab, height=5, width=100)
        self.raw_output.pack()

    def decode_qr(self):
        try:
            text = self.qr_input.get("1.0", tk.END).strip()
            segments = parse_tlv(text)
            result = extract_json_model(segments)
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, json.dumps(result, indent=2))
        except Exception as e:
            messagebox.showerror("Decode Error", str(e))

    def generate_qr(self):
        try:
            raw = self.json_input.get("1.0", tk.END)
            json_obj = json.loads(raw)
            payload = build_qr_from_json(json_obj)
            qr_img = qrcode.make(payload).resize((300, 300))
            self.tk_img = ImageTk.PhotoImage(qr_img)
            self.canvas.create_image(0, 0, anchor=tk.NW, image=self.tk_img)
            self.raw_output.delete("1.0", tk.END)
            self.raw_output.insert(tk.END, payload)
        except Exception as e:
            messagebox.showerror("Generate Error", str(e))


if __name__ == '__main__':
    root = tk.Tk()
    ThaiQRGUI(root)
    root.mainloop()
