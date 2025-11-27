from docx import Document
from pprint import pprint

def extract_docx_metadata(docx_file: str):
    doc = Document(docx_file)
    core_properties = doc.core_properties

    metadata = {}

    # Core properties
    for prop in dir(core_properties):
        if prop.startswith("__"):
            continue

        value = getattr(core_properties, prop)

        if callable(value):
            continue

        # Fix datetime fields
        if prop in ["created", "modified", "last_printed"]:
            if value:
                value = value.strftime("%Y-%m-%d %H:%M:%S")
            else:
                value = None

        metadata[prop] = value

    # Custom properties (if available)
    try:
        custom_props = core_properties.custom_properties
        if custom_props:
            metadata["custom_properties"] = {
                prop.name: prop.value for prop in custom_props
            }
    except AttributeError:
        pass

    print("\n=== DOCX METADATA ===")
    pprint(metadata)
