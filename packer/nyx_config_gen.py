#!/usr/bin/env python

from jinja2 import Template, Environment
import sys, os
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN
from common.self_check import self_check
from common.util import ask_for_permission
from common.info import show_banner
import glob, shutil

template_kernel_default = \
  """
  #![enable(implicit_some)]
  (
      runner: QemuKernel((
        qemu_binary: "{{ default_qemu }}",
        kernel: "{{ default_kernel_path }}",
        ramfs: "{{ default_init_ramfs }}",
        debug: false,
      )),
      fuzz: (
          workdir_path: "/tmp/workdir",
          bitmap_size: 65536,
          mem_limit: 512,
          time_limit: (
              secs: 0,
              nanos: 80000000,
          ),
          threads: 1,
          thread_id: 0,
          cpu_pin_start_at: 0,
          snapshot_placement: none,
          seed_path: "",
          dict: []
      ),
  )
  """

template_vm_default = \
  """
  #![enable(implicit_some)]
  (
      runner: QemuSnapshot((
        qemu_binary: "{{ default_qemu }}",
        hda: "{{ default_vm_hda }}",
        presnapshot: "{{ default_vm_presnapshot }}",
        snapshot_path: DefaultPath,
        debug: false,
      )),
      fuzz: (
          workdir_path: "/tmp/workdir",
          bitmap_size: 65536,
          mem_limit: 512,
          time_limit: (
              secs: 0,
              nanos: 80000000,
          ),
        threads: 1,
          thread_id: 0,
          cpu_pin_start_at: 0,
        snapshot_placement: none,
        seed_path: "",
        dict: []
      ),
  )
  """


template_kernel = \
  """
#![enable(implicit_some)]
(
    include_default_config_path: "{{ default_config_path }}",
    runner: QemuKernel((
      //debug: false,
    )
  ),
  fuzz: (
    workdir_path: "{{ default_workdir }}",
  {% if mem %}
    mem_limit: {{ mem }},
  {% else %}
    //mem_limit: 512,
  {%endif %}
  {% if seed_path %}
    seed_path: "{{ seed_path }}",
  {%else%}
  seed_path: "",
  {%endif %}
    dict: [
  {% if dict_entries %}          {{ dict_entries }}{%endif %}
    ],
  {% if disable_timeouts %}
    time_limit: (
      secs: 0,
      nanos: 0,       
    ),
  {%endif %}
  {% if sec != 0 or nanos != 0 %}
    time_limit: (
      secs: {{ sec }},
      nanos: {{ nanos }},       
    ),
  {%endif %}
  ip0: (
        a: 0,
        b: 0,
      ),
      ip1: (
        a: 0,
        b: 0,
      ),
      ip2: (
        a: 0,
        b: 0,
      ),
      ip3: (
        a: 0,
        b: 0,
      ),
  ),
)
  """

template_vm = \
  """
#![enable(implicit_some)]
(
    include_default_config_path: "{{ default_config_path }}",
    runner: QemuSnapshot((
        //debug: false,
    )
  ),
  fuzz: (
    workdir_path: "{{ default_workdir }}",
  {% if mem %}        mem_limit: {{ mem }},{%endif %}
          //snapshot_placement: none,
  {% if seed_path %}        seed_path: "{{ seed_path }}",{%endif %}
          dict: [
  {% if dict_entries %}          {{ dict_entries }}{%endif %}
          ],
  {% if disable_timeouts %}
          time_limit: (
              secs: 0,
              nanos: 0,       
            ),
  {%endif %}
  {% if sec != 0 or nanos != 0 %}
          time_limit: (
              secs: {{ sec }},
              nanos: {{ nanos }},       
            ),
  {%endif %}
  ip0: (
        a: 0,
        b: 0,
      ),
      ip1: (
        a: 0,
        b: 0,
      ),
      ip2: (
        a: 0,
        b: 0,
      ),
      ip3: (
        a: 0,
        b: 0,
      ),
  ),
)
  """


def get_default_kernel_config(qemu_path, default_kernel_path, default_init_ramfs):
  data = { 
    "default_qemu":  qemu_path,
    "default_kernel_path": default_kernel_path,
    "default_init_ramfs": default_init_ramfs,
  }

  env = Environment(trim_blocks=True)
  template = env.from_string(template_kernel_default)
  return template.render(data)

def get_default_vm_config(qemu_path, default_vm_hda, default_vm_presnapshot):
  data = { 
    "default_qemu":  qemu_path,
    "default_vm_hda": default_vm_hda,
    "default_vm_presnapshot": default_vm_presnapshot,
  }

  env = Environment(trim_blocks=True)
  template = env.from_string(template_vm_default)
  return template.render(data)

def get_config(template_file, default_config_path, default_workdir, mem=None, seed_path=None, dict_entries=None, timeout_options=None):
  data = { 
    "default_config_path":  default_config_path,
    "default_workdir":      default_workdir,
  }

  if mem:
    data['mem'] = mem

  if seed_path:
    data['seed_path'] = seed_path

  if dict_entries:
    data['dict_entries'] = dict_entries

  if timeout_options:
    if timeout_options['disabled']:
      data['disable_timeouts'] = True
      data['sec'] = 0
      data['nanos'] = 0
    elif timeout_options['sec'] != 0 or timeout_options['nanos'] != 0:
      data['sec'] = timeout_options['sec']
      data['nanos'] = timeout_options['nanos']
    else:
      data['sec'] = 0
      data['nanos'] = 0

  env = Environment(trim_blocks=True)
  template = env.from_string(template_file)
  return template.render(data)

def gen_kernel_config(default_config_path, default_workdir, mem=None, seed_path=None, dict_entries=None, timeout_options=None):
  return get_config(template_kernel, default_config_path, default_workdir, mem=mem, seed_path=seed_path, dict_entries=dict_entries, timeout_options=timeout_options)

def gen_vm_config(default_config_path, default_workdir, mem=None, seed_path=None, dict_entries=None, timeout_options=None):
  return get_config(template_vm, default_config_path, default_workdir, mem=mem, seed_path=seed_path, dict_entries=dict_entries, timeout_options=timeout_options)

def to_hex(string):
  try:
    data = bytes(string, "ascii").decode("unicode_escape")
  except:
      data = bytes(string).decode("unicode_escape")

  return "[" + ','.join([str(ord(i)) for i in data]) + "], //%s"%(string)

def convert_dict(path_to_dict_file):
  output = ""
  with open(path_to_dict_file, 'r') as dict_file:
    while True:
      line = dict_file.readline()
      if not line:
        break
      try:
        content = line.split("=")[1].replace("\"", "").replace("\n", "")
        if len(content) > 0:
          output += "%s\n"%(to_hex(content))
      except:
        content = line.replace("\"", "").replace("\n", "")
        if len(content) > 0:
          output += "%s\n"%(to_hex(content))

  return output



def gen_nyx_config(config):

  data = {}
  config_content = ""

  timeout = {"disabled": False, "sec": 0, "nanos": 0}

  if config.argument_values["m"]:
    data["mem"] = config.argument_values["m"]
  
  if config.argument_values["w"]:
    data["workdir"] = config.argument_values["w"]
  else:
    data["workdir"] = "/tmp/workdir"

  if config.argument_values["d"]:
    data["dict_entries"] = convert_dict(config.argument_values["d"])
  else:
    data["dict_entries"] = None


  if config.argument_values["n"]:
    timeout['nanos'] = config.argument_values["n"]

  if config.argument_values["s"]:
    data["seed_path"] = "seeds/"
  else:
    data["seed_path"] = None

  if config.argument_values["disable_timeouts"]:
    timeout["disabled"] = True

  if config.argument_values["path_to_default_config"]:
    data["default_config"] = config.argument_values["path_to_default_config"]
  else:
    if config.argument_values["vm_type"] == "Kernel":
      data["default_config"] = config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_kernel.ron"
    else:
      data["default_config"] = config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_vm.ron"

  if config.argument_values["vm_type"] == "Kernel":
    config_content = gen_kernel_config( \
          data["default_config"], \
          data["workdir"], \
          mem=data["mem"], \
          seed_path=data["seed_path"], \
          dict_entries=data["dict_entries"], \
          timeout_options=timeout \
    )

  elif config.argument_values["vm_type"] == "Snapshot":
    config_content = gen_vm_config( \
          data["default_config"], \
          data["workdir"], \
          mem=data["mem"], \
          seed_path=data["seed_path"], \
          dict_entries=data["dict_entries"], \
          timeout_options=timeout \
    )
  else:
    raise Exception("Unkown VM Type <%s>"%(config.argument_values["vm_type"]))

  f = open(config.argument_values["share_dir"] + "/config.ron", "w")
  f.write(config_content)
  f.close()

  if config.argument_values["s"]:
    seed_counter = 0
    os.mkdir("%s/seeds/"%(config.argument_values["share_dir"]))
    for file_name in glob.glob(os.path.abspath(config.argument_values["s"]) + "/*.bin"):
      shutil.copyfile(file_name, "%s/seeds/seed_%d.bin"%(config.argument_values["share_dir"], seed_counter))
      seed_counter += 1
    for file_name in glob.glob(os.path.abspath(config.argument_values["s"]) + "/*/*.bin"):
      shutil.copyfile(file_name, "%s/seeds/seed_%d.bin"%(config.argument_values["share_dir"], seed_counter))
      seed_counter += 1


def gen_default_configs(config):
  if config.argument_values["vm_type"] == "Kernel" and not os.path.isfile(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_kernel.ron"):
    print("AUTOGEN default_config_kernel.ron")
    f = open(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_kernel.ron", "w")
    f.write(get_default_kernel_config(config.config_values['QEMU-PT_PATH'], config.config_values['KERNEL'], config.config_values['INIT_RAMFS']))
    f.close()

  if config.argument_values["vm_type"] == "Snapshot" and not os.path.isfile(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_vm.ron"):
    print("AUTOGEN default_config_vm.ron")

    if config.config_values['DEFAULT_VM_HDA'] == "":
      print("ERROR: DEFAULT_VM_HDA is empty (fix nyx.ini)")
      sys.exit(1)

    if config.config_values['DEFAULT_VM_PRESNAPSHOT'] == "":
      print("ERROR: DEFAULT_VM_PRESNAPSHOT is empty (fix nyx.ini)")
      sys.exit(1)

    f = open(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_vm.ron", "w")
    f.write(get_default_vm_config(config.config_values['QEMU-PT_PATH'], config.config_values['DEFAULT_VM_HDA'], config.config_values['DEFAULT_VM_PRESNAPSHOT']))
    f.close()


def main():

    from common.config import ConfigGeneratorConfiguration
    config = ConfigGeneratorConfiguration()

    if not config.argument_values["path_to_default_config"]:
      gen_default_configs(config)

    if not self_check():
        return 1

    gen_nyx_config(config)


if __name__ == "__main__":
    main()