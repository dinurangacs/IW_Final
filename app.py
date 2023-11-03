from flask import Flask, redirect, render_template, request , flash, url_for
import pefile
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras import Sequential
from tensorflow.keras.activations import sigmoid
from tensorflow.python.keras.models import load_model
from flask_mail import Mail, Message
import pandas as pd
import numpy as np
from datetime import datetime
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'malwaredetection00@gmail.com'
app.config['MAIL_PASSWORD'] = 'okwkedrhpadfttus'
#'MALWAREdetection900'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
# Features from the downloaded pe file
content = []
with open('suspicious_functions.txt') as f:
    content = f.readlines()
content = [x.strip() for x in content]
name_packers = []
with open('name_packers.txt') as f:
    name_packers = f.readlines()
name_packers = [x.strip() for x in name_packers]
def get_features(pe):
    count_suspicious_functions = 0
    number_packers = 0

    entropy = map(lambda x: x.get_entropy(), pe.sections)
    raw_sizes = map(lambda x: x.SizeOfRawData, pe.sections)
    virtual_sizes = map(lambda x: x.Misc_VirtualSize, pe.sections)
    physical_address = map(lambda x: x.Misc_PhysicalAddress, pe.sections)
    virtual_address = map(lambda x: x.VirtualAddress, pe.sections)
    pointer_raw_data = map(lambda x: x.PointerToRawData, pe.sections)
    characteristics = map(lambda x: x.Characteristics, pe.sections)

    data = {'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'e_magic': pe.DOS_HEADER.e_magic,
            'e_cblp': pe.DOS_HEADER.e_cblp,
            'e_cp': pe.DOS_HEADER.e_cp,
            'e_crlc': pe.DOS_HEADER.e_crlc,
            'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
            'e_minalloc': pe.DOS_HEADER.e_minalloc,
            'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
            'e_ss': pe.DOS_HEADER.e_ss,
            'e_sp': pe.DOS_HEADER.e_sp,
            'e_csum': pe.DOS_HEADER.e_csum,
            'e_ip': pe.DOS_HEADER.e_ip,
            'e_cs': pe.DOS_HEADER.e_cs,
            'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
            'e_ovno': pe.DOS_HEADER.e_ovno,
            'e_oemid': pe.DOS_HEADER.e_oemid,
            'e_oeminfo': pe.DOS_HEADER.e_oeminfo,
            'e_lfanew': pe.DOS_HEADER.e_lfanew,
            'Machine': pe.FILE_HEADER.Machine,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'PointerToSymbolTable': pe.FILE_HEADER.PointerToSymbolTable,
            'NumberOfSymbols': pe.FILE_HEADER.NumberOfSymbols,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Magic': pe.OPTIONAL_HEADER.Magic,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            }

    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                if func.name.decode('utf-8') in content:
                    count_suspicious_functions += 1
        data['SuspiciousImportFunctions'] = count_suspicious_functions
    except AttributeError:
        data['SuspiciousImportFunctions'] = 0

    try:
        for entry in pe.sections:
            try:
                entry.Name.decode('utf-8')
            except Exception:
                number_packers += 1
            if entry.Name in name_packers:
                number_packers += 1

        data['SuspiciousNameSection'] = number_packers
    except AttributeError as e:
        data['SuspiciousNameSection'] = 0
    try:
        data['SectionsLength'] = len(pe.sections)
    except (ValueError, TypeError):
        data['SectionsLength'] = 0
    try:
        data['SectionMinEntropy'] = min(entropy)
    except (ValueError, TypeError):
        data['SectionMinEntropy'] = 0
    try:
        data['SectionMaxEntropy'] = max(entropy)
    except (ValueError, TypeError):
        data['SectionMaxEntropy'] = 0
    try:
        data['SectionMinRawsize'] = min(raw_sizes)
    except (ValueError, TypeError):
        data['SectionMinRawsize'] = 0
    try:
        data['SectionMaxRawsize'] = max(raw_sizes)
    except (ValueError, TypeError):
        data['SectionMaxRawsize'] = 0
    try:
        data['SectionMinVirtualsize'] = min(virtual_sizes)
    except (ValueError, TypeError):
        data['SectionMinVirtualsize'] = 0
    try:
        data['SectionMaxVirtualsize'] = max(virtual_sizes)
    except (ValueError, TypeError):
        data['SectionMaxVirtualsize'] = 0
    try:
        data['SectionMaxVirtualsize'] = max(virtual_sizes)
    except (ValueError, TypeError):
        data['SectionMaxVirtualsize'] = 0

    try:
        data['SectionMaxPhysical'] = max(physical_address)
    except (ValueError, TypeError):
        data['SectionMaxPhysical'] = 0
    try:
        data['SectionMinPhysical'] = min(physical_address)
    except (ValueError, TypeError):
        data['SectionMinPhysical'] = 0

    try:
        data['SectionMaxVirtual'] = max(virtual_address)
    except (ValueError, TypeError):
        data['SectionMaxVirtual'] = 0
    try:
        data['SectionMinVirtual'] = min(virtual_address)
    except (ValueError, TypeError):
        data['SectionMinVirtual'] = 0

    try:
        data['SectionMaxPointerData'] = max(pointer_raw_data)
    except (ValueError, TypeError):
        data['SectionMaxPointerData'] = 0

    try:
        data['SectionMinPointerData'] = min(pointer_raw_data)
    except (ValueError, TypeError):
        data['SectionMinPointerData'] = 0

    try:
        data['SectionMaxChar'] = max(characteristics)
    except (ValueError, TypeError):
        data['SectionMaxChar'] = 0

    try:
        data['SectionMinChar'] = min(characteristics)
    except (ValueError, TypeError):
        data['SectionMainChar'] = 0

    try:
        data['DirectoryEntryImport'] = (len(pe.DIRECTORY_ENTRY_IMPORT))
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        data['DirectoryEntryImportSize'] = (len(imports))
    except AttributeError:
        data['DirectoryEntryImport'] = 0
        data['DirectoryEntryImportSize'] = 0
    # Exports
    try:
        data['DirectoryEntryExport'] = (len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    except AttributeError:
        # No export
        data['DirectoryEntryExport'] = 0

    data['ImageDirectoryEntryExport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
    data['ImageDirectoryEntryImport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    data['ImageDirectoryEntryResource'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress
    data['ImageDirectoryEntryException'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].VirtualAddress
    data['ImageDirectoryEntrySecurity'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

    return data


def norm(x, train_stats):
    return (x - train_stats['mean']) / train_stats['std']

@app.route('/', methods =['GET']) 
def render():
    return render_template('index.html')

@app.route('/uploadFile', methods =['POST']) 
def uploadFile():
    file = request.files['file']
    filePath = "./DownloadedFiles/"+ file.filename
    
    file.save(filePath)
    exe_file = pefile.PE(filePath)
    features = get_features(exe_file)
    ds = pd.read_csv('train_dataset.csv')
    ds.drop(['Unnamed: 0'], axis=1, inplace=True)
    ds.drop(['Name'], axis=1, inplace=True)
    ls = []
    cols = ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc',
            'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc',
            'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew', 'Machine',
            'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable',
            'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics', 'Magic',
            'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
            'SizeOfInitializedData', 'SizeOfUninitializedData',
            'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment',
            'FileAlignment', 'MajorOperatingSystemVersion',
            'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
            'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfHeaders',
            'CheckSum', 'SizeOfImage', 'Subsystem', 'DllCharacteristics',
            'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
            'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes',
            'SuspiciousImportFunctions', 'SuspiciousNameSection', 'SectionsLength',
            'SectionMinEntropy', 'SectionMaxEntropy', 'SectionMinRawsize',
            'SectionMaxRawsize', 'SectionMinVirtualsize', 'SectionMaxVirtualsize',
            'SectionMaxPhysical', 'SectionMinPhysical', 'SectionMaxVirtual',
            'SectionMinVirtual', 'SectionMaxPointerData', 'SectionMinPointerData',
            'SectionMaxChar', 'SectionMainChar', 'DirectoryEntryImport',
            'DirectoryEntryImportSize', 'DirectoryEntryExport',
            'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport',
            'ImageDirectoryEntryResource', 'ImageDirectoryEntryException',
            'ImageDirectoryEntrySecurity']
    for i in cols:
        ls.append(features[i])
    ds = pd.concat([ds, pd.DataFrame([ls], columns=cols)], ignore_index=True)
    train_stats = ds.describe()
    train_stats = train_stats.transpose()
    normed_train_data = norm(ds, train_stats)
    normed_train_data = normed_train_data.dropna(axis=1, how='all')
    # print("This is the sorted ", normed_train_data.columns)
   # s = sorted(normed_train_data.columns)
    ds = normed_train_data.reindex(sorted(normed_train_data.columns), axis=1)
    normalized_pefile = ds.iloc[-1]
    normalized_pefile = list(normalized_pefile)
    arr = np.array(normalized_pefile)
    reshaped_test_features = arr.reshape(1, len(normalized_pefile), 1)
    model = load_model("Malware_Detection_Model.h5")
    pred = model.predict(reshaped_test_features)
    Final_Output = np.argmax(pred, axis=1)  # index of highest element
    res = ""
    if(Final_Output[0]==1):
        res = "The file is malicious"
        flash(" ", 'error')
    else:
        res = "The file is benign"
        flash(" ", 'success')
    return redirect(url_for("index") + "#uploadSection")
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scroll-to/<string:scroll_id>")
def scroll_to(scroll_id):
    return redirect(url_for("index") + "#" + scroll_id)

@app.route("/contact", methods =['POST'])
def contact():
    name = request.form['name']
    email = request.form['email']
    message = request.form['msg']
    msg = Message("Message from "+name,sender='nonreply@malwaredetection.com',
                  recipients=['malwaredetection00@gmail.com'])
    msg.body = "From "+name+"\n"+message+"\nEmail: "+email
    mail.send(msg)
    flash("Email sent successfully!")
    return redirect(url_for("index") + "#Contact")
if __name__ == '__main__':
    app.run(port=3000, debug=True)

