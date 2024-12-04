from collections import OrderedDict

def map_verbose_keys(json_res, proto_td):
    def recursive_map(json_obj, proto_obj):
        if isinstance(json_obj, dict):
            json_keys = list(json_obj.keys())
            proto_keys = list(proto_obj.keys())

            for json_key, proto_key in zip(json_keys, proto_keys):
                json_value = json_obj[json_key]
                proto_field = proto_obj[proto_key]

                if proto_field.get("name") == "":
                    proto_field["name"] = json_key

                if isinstance(json_value, dict) and "message_typedef" in proto_field:
                    recursive_map(json_value, proto_field["message_typedef"])

                elif isinstance(json_value, list) and "message_typedef" in proto_field:
                    for item in json_value:
                        recursive_map(item, proto_field["message_typedef"])

        elif isinstance(json_obj, list):  # Handle lists
            for item in json_obj:
                recursive_map(item, proto_obj)

    recursive_map(json_res, proto_td)


def recursive_merge(type_def1, type_def2):
    for key, value in type_def2.items():
        if key in type_def1:
            if type_def1[key]["type"] == "message":
                recursive_merge(type_def1[key]["message_typedef"], value["message_typedef"])

        else:
            type_def1[key] = value


if __name__ == "__main__":
    import os
    import sys
    import json
    import inspect

    # Import blackboxprotobuf
    _BASE_DIR = os.path.abspath(os.path.dirname(inspect.getfile(inspect.currentframe())))

    sys.path.insert(0, _BASE_DIR + "/blackboxprotobuf/lib/")
    sys.path.insert(0, _BASE_DIR + "/blackboxprotobuf/burp/deps/six/")
    sys.path.insert(0, _BASE_DIR + "/blackboxprotobuf/burp/deps/protobuf/python/")

    # Hack to fix loading protobuf libraries within Jython. See https://github.com/protocolbuffers/protobuf/issues/7776
    def fix_protobuf():
        import six

        u = six.u

        def new_u(s):
            if s == r"[\ud800-\udfff]":
                # Don't match anything
                return "$^"
            else:
                return u(s)

        six.u = new_u

    fix_protobuf()

    import blackboxprotobuf

    # proto_file = open("/Users/lorenzo.di.fuccia/Desktop/browse_proto.raw", "rb")
    proto_file = open(sys.argv[1], "rb")
    proto_message, proto_typedef = blackboxprotobuf.protobuf_to_json(proto_file.read())

    # json_file = open("/Users/lorenzo.di.fuccia/Desktop/browse_proto.json")
    json_file = open(sys.argv[2])
    json_response = json.load(json_file, object_pairs_hook=OrderedDict)

    map_verbose_keys(json_response, proto_typedef)

    print(json.dumps(proto_typedef))
