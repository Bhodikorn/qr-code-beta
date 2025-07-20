# Thai QR Code Tool with JSON Editing, Summary, and Validation Check (Extended: Multi-segment + Tag 30/31)

import tkinter as tk
from tkinter import ttk, messagebox
import qrcode
from PIL import Image, ImageTk
import crcmod.predefined
import json
import re


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


def parse_nested_tlv(value):
    segments = []
    i = 0
    while i < len(value):
        tag = value[i:i+2]
        length = int(value[i+2:i+4])
        val = value[i+4:i+4+length]
        segments.append({"Id": tag, "Length": f"{length:02d}", "Value": val})
        i += 4 + length
    return segments


def calculate_crc(payload):
    crc16 = crcmod.predefined.mkCrcFun('crc-ccitt-false')
    return f"{crc16((payload + '6304').encode('utf-8')):04X}"


def extract_json_model(segments):
    model = {"Segments": segments, "Reusable": any(s["Id"] == "01" and s["Value"] == "11" for s in segments)}
    tag_map = {s["Id"]: s["Value"] for s in segments}
    if "30" in tag_map:
        model["BillPayment"] = parse_nested_tlv(tag_map["30"])
    if "31" in tag_map:
        model["API"] = parse_nested_tlv(tag_map["31"])
    return model


def build_qr_from_json(json_obj):
    payload = ""
    for seg in json_obj.get("Segments", []):
        if seg["Id"] != "63":
            payload += encode_tlv(seg["Id"], seg["Value"])
    crc = calculate_crc(payload)
    payload += encode_tlv("63", crc)
    return payload


def validate_json_structure(json_obj):
    try:
        if isinstance(json_obj, str) and json_obj.strip().startswith("00"):
            json_obj = extract_json_model(parse_tlv(json_obj.strip()))
        assert isinstance(json_obj, dict)
        assert "Segments" in json_obj
        for seg in json_obj["Segments"]:
            tag = seg["Id"]
            val = seg["Value"]
            if tag == "54":  # amount
                assert re.match(r'^\d{1,13}(\.\d{1,2})?$', val)
            if tag == "53":  # currency
                assert val.isdigit() and len(val) == 3
            if tag == "58":  # country
                assert re.match(r'^[A-Z]{2}$', val)
        return True, "✅ JSON structure is valid.", json_obj
    except Exception as e:
        return False, f"❌ Invalid JSON structure: {e}", None


def get_summary_text(model):
    tag_map = {seg["Id"]: seg["Value"] for seg in model.get("Segments", [])}
    type_str = "Unknown"
    if "29" in tag_map:
        type_str = "Credit Transfer"
    elif "30" in tag_map:
        type_str = "Bill Payment"
    elif "31" in tag_map:
        type_str = "API (Standard/Acquirer Specific)"

    lines = [
        f"Type: {type_str}",
        f"Reusable: {'Yes' if model.get('Reusable') else 'No'}",
        f"Amount: {tag_map.get('54')}",
        f"Name: {tag_map.get('59')}",
        f"City: {tag_map.get('60')}",
        f"Country: {tag_map.get('58')}",
    ]
    if "29" in tag_map and "0113" in tag_map["29"]:
        lines.append(f"Mobile: {tag_map['29'][-10:]}")
    if model.get("BillPayment"):
        for sub in model["BillPayment"]:
            if sub["Id"] == "01":
                lines.append(f"Biller ID: {sub['Value']}")
            if sub["Id"] == "02":
                lines.append(f"Ref1: {sub['Value']}")
            if sub["Id"] == "03":
                lines.append(f"Ref2: {sub['Value']}")
    if model.get("API"):
        for sub in model["API"]:
            if sub["Id"] == "01":
                lines.append(f"API ID: {sub['Value']}")
    return "\n".join(filter(None, lines))


class ThaiQRGUI:
    def __init__(self, root):
        root.title("Thai QR Code Tool")

        self.tab = ttk.Notebook(root)
        self.decode_tab = ttk.Frame(self.tab)
        self.generate_tab = ttk.Frame(self.tab)
        self.modify_tab = ttk.Frame(self.tab)
        self.validate_tab = ttk.Frame(self.tab)

        self.tab.add(self.decode_tab, text='Decode')
        self.tab.add(self.generate_tab, text='Generate')
        self.tab.add(self.modify_tab, text='Modify')
        self.tab.add(self.validate_tab, text='Validate')
        self.tab.pack(expand=1, fill='both')

        # Decode Tab
        ttk.Label(self.decode_tab, text="Paste QR Payload to Decode:").pack()
        self.qr_input = tk.Text(self.decode_tab, height=5, width=80)
        self.qr_input.pack()
        ttk.Button(self.decode_tab, text="Parse JSON", command=self.decode_qr).pack(pady=5)
        self.output = tk.Text(self.decode_tab, height=25, width=100)
        self.output.pack()

        # Generate Tab
        ttk.Label(self.generate_tab, text="Paste JSON or QR Payload to Encode:").pack()
        self.json_input = tk.Text(self.generate_tab, height=20, width=100)
        self.json_input.pack()
        ttk.Button(self.generate_tab, text="Generate QR", command=self.generate_qr).pack(pady=5)
        self.canvas = tk.Canvas(self.generate_tab, width=300, height=300)
        self.canvas.pack()
        self.raw_output = tk.Text(self.generate_tab, height=5, width=100)
        self.raw_output.pack()

        # Modify Tab - JSON + Summary
        ttk.Label(self.modify_tab, text="Summary:").pack()
        self.summary_text = tk.Text(self.modify_tab, height=6, width=100, bg="#f5f5f5")
        self.summary_text.pack()

        ttk.Label(self.modify_tab, text="Edit JSON:").pack()
        self.modify_json = tk.Text(self.modify_tab, height=20, width=100)
        self.modify_json.pack()
        ttk.Button(self.modify_tab, text="Generate QR from Modify", command=self.generate_from_modify).pack(pady=5)
        self.canvas_mod = tk.Canvas(self.modify_tab, width=300, height=300)
        self.canvas_mod.pack()
        self.payload_mod = tk.Text(self.modify_tab, height=5, width=100)
        self.payload_mod.pack()

        # Validate Tab
        ttk.Label(self.validate_tab, text="Paste JSON or QR Payload to Validate:").pack()
        self.validate_input = tk.Text(self.validate_tab, height=20, width=100)
        self.validate_input.pack()
        ttk.Button(self.validate_tab, text="Check Validity", command=self.validate_json).pack(pady=5)
        self.validate_output = tk.Label(self.validate_tab, text="")
        self.validate_output.pack()

    def decode_qr(self):
        try:
            text = self.qr_input.get("1.0", tk.END).strip()
            segments = parse_tlv(text)
            model = extract_json_model(segments)
            json_text = json.dumps(model, indent=2)
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, json_text)
            self.modify_json.delete("1.0", tk.END)
            self.modify_json.insert(tk.END, json_text)
            self.summary_text.delete("1.0", tk.END)
            self.summary_text.insert(tk.END, get_summary_text(model))
        except Exception as e:
            messagebox.showerror("Decode Error", str(e))

    def generate_qr(self):
        try:
            raw = self.json_input.get("1.0", tk.END).strip()
            if raw.startswith("00"):
                segments = parse_tlv(raw)
                json_obj = extract_json_model(segments)
            else:
                json_obj = json.loads(raw)
            valid, msg, obj = validate_json_structure(json_obj)
            if not valid:
                messagebox.showerror("Invalid JSON", msg)
                return
            payload = build_qr_from_json(obj)
            qr_img = qrcode.make(payload).resize((300, 300))
            self.tk_img = ImageTk.PhotoImage(qr_img)
            self.canvas.create_image(0, 0, anchor=tk.NW, image=self.tk_img)
            self.raw_output.delete("1.0", tk.END)
            self.raw_output.insert(tk.END, payload)
        except Exception as e:
            messagebox.showerror("Generate Error", str(e))

    def generate_from_modify(self):
        try:
            raw = self.modify_json.get("1.0", tk.END)
            json_obj = json.loads(raw)
            valid, msg, obj = validate_json_structure(json_obj)
            if not valid:
                messagebox.showerror("Invalid JSON", msg)
                return
            payload = build_qr_from_json(obj)
            qr_img = qrcode.make(payload).resize((300, 300))
            self.tk_img_mod = ImageTk.PhotoImage(qr_img)
            self.canvas_mod.create_image(0, 0, anchor=tk.NW, image=self.tk_img_mod)
            self.payload_mod.delete("1.0", tk.END)
            self.payload_mod.insert(tk.END, payload)
            self.summary_text.delete("1.0", tk.END)
            self.summary_text.insert(tk.END, get_summary_text(obj))
        except Exception as e:
            messagebox.showerror("Modify Generate Error", str(e))

    def validate_json(self):
        try:
            raw = self.validate_input.get("1.0", tk.END).strip()
            if raw.startswith("00"):
                segments = parse_tlv(raw)
                json_obj = extract_json_model(segments)
            else:
                json_obj = json.loads(raw)
            valid, msg, _ = validate_json_structure(json_obj)
            self.validate_output.config(text=msg)
        except Exception as e:
            self.validate_output.config(text=f"Error: {e}")


if __name__ == '__main__':
    root = tk.Tk()
    ThaiQRGUI(root)
    root.mainloop()
