import sys

DISALLOWED_CHARACTERS = "*\n\r\t?;"
RES = ""

def clean_list(path_list):
    res = []
    for path in path_list:
        for c in DISALLOWED_CHARACTERS:
            path = path.replace(c,"")
        if path != "":
            res += [path]
    return res

def split_paths(l):
    result = {}
    for directory in l:
        splited_directories = directory.split("/")
        splited_directories = clean_list(splited_directories)
        last_keys = []
        for folder in splited_directories:
            if last_keys == []:
                if folder not in result:
                    result[folder] = {}
                last_keys.append(folder)
            else:
                temp = result
                for last in last_keys:
                    temp = temp[last]
                if folder not in temp:
                    temp[folder] = {}
                last_keys.append(folder)
    return result

def make_tree(directories, before=""):
    global RES
    space =  '    '
    branch = '|   '
    tee =    '|---'
    last =   '\___'
    count = 0
    length = len(directories)
    for d in directories:
        if length == 1:
            RES += before+last+d+"\n"
        elif count == 0:
            RES += before+tee+d+"\n"
        elif count < length-1:
            RES += before+tee+d+"\n"
        else:
            RES += before+last+d+"\n"
        if count == length-1:
            make_tree(directories[d], before+space)
        else:
            make_tree(directories[d], before+branch)
        count+=1

def start(l):
    global RES
    make_tree(split_paths(l))
    temp = RES
    RES = ""
    return temp