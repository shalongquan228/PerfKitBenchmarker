# Copyright 2014 PerfKitBenchmarker Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module containing classes related to AWS disks.

Disks can be created, deleted, attached to VMs, and detached from VMs.
See http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html to
determine valid disk types.
See http://aws.amazon.com/ebs/details/ for more information about AWS (EBS)
disks.
"""

import json
import logging
import string
import threading

from perfkitbenchmarker import providers
from perfkitbenchmarker import resource
from perfkitbenchmarker import vm_util
from perfkitbenchmarker.configs import option_decoders
from perfkitbenchmarker.providers.aws import util


NETWORK_INTERFACE_EXISTS_STATUS = frozenset(
    ['available', 'in-use'])
NETWORK_INTERFACE_KNOWN_STATUS = NETWORK_INTERFACE_EXISTS_STATUS

NUM_NETWORK_INTERFACES = {
    'c1.medium': 2, 'c1.xlarge': 4,
    'c3.large': 3, 'c3.xlarge': 4, 'c3.2xlarge': 4, 'c3.4xlarge': 8,
    'c3.8xlarge': 8,
    'c4.large': 3, 'c4.xlarge': 4, 'c4.2xlarge': 4, 'c4.4xlarge': 8,
    'c4.8xlarge': 8, 'cc2.8xlarge': 8,
    'cg1.4xlarge': 8, 'cr1.8xlarge': 8, 'g2.2xlarge': 4, 'g2.8xlarge': 8,
    'hi1.4xlarge': 8, 'hs1.8xlarge': 8,
    'i2.xlarge': 4, 'i2.2xlarge': 4, 'i2.4xlarge': 8, 'i2.8xlarge': 8,
    'm1.small': 2, 'm1.medium': 2, 'm1.large': 3, 'm1.xlarge': 4,
    'm2.xlarge': 4, 'm2.2xlarge': 8, 'm2.4xlarge': 8,
    'm3.medium': 2, 'm3.large': 4, 'm3.xlarge': 4, 'm3.2xlarge': 8,
    'r3.large': 4, 'r3.xlarge': 4, 'r3.2xlarge': 8, 'r3.4xlarge': 8,
    'r3.8xlarge': 8, 'd2.xlarge': 4, 'd2.2xlarge': 4, 'd2.4xlarge': 8,
    'd2.8xlarge': 8, 'x1.32xlarge': 2, 't1.micro': 2, 't2.nano': 2,
    't2.medium':3, 't2.large': 3,
}


class AwsNetworkInterface(resource.BaseResource):
  """An object representing an Aws Network Interface."""

  _lock = threading.Lock()
  vm_devices = {}

  def __init__(self, network):
    """Initialize a Aws Network Interface."""
    super(AwsNetworkInterface, self).__init__(network)
    self.id = None
    self.network = network
    self.internal_ip = None
    self.device_letter = None
    self.attached_vm_id = None

  def _Create(self):
    """Creates the network interface."""
    create_cmd = util.AWS_PREFIX + [
        'ec2',
        'create-network-interface',
        '--subnet-id=%s' % self.network.subnet.id,
        '--groups=%s' % self.network.regional_network.vpc
        .default_security_group_id]
    stdout, _, _ = vm_util.IssueCommand(create_cmd)
    response = json.loads(stdout)
    self.id = response['NetworkInterface']['NetworkInterfaceId']
    self.internal_ip = response['NetworkInterface']['PrivateIpAddress']
    region = response['NetworkInterface']['AvailabilityZone'][:-1]
    util.AddDefaultTags(self.id, region)

  def _Delete(self):
    """Delete the network interface."""
    delete_cmd = util.AWS_PREFIX + [
        'ec2',
        'delete-network-interface',
        '--network-interface-id=%s' % self.id]
    logging.info('Deleting AWS network interface %s. This may fail if the '
                 'network interface is not yet detached, but will be retried',
                 self.id)
    vm_util.IssueCommand(delete_cmd)

  def _Exists(self):
    """Returns true if the network interface exists."""
    describe_cmd = util.AWS_PREFIX + [
        'ec2',
        'describe-network-interfaces',
        '--network-interface-id=%s' % self.id]
    stdout, _ = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    enis = response['NetworkInterfaces']
    assert len(enis) < 2, 'Too many network interfaces.'
    if not enis:
      return False
    status = enis[0]['Status']
    assert status in NETWORK_INTERFACE_KNOWN_STATUS, status
    return status in NETWORK_INTERFACE_EXISTS_STATUS

  def Attach(self, vm):
    """Attaches the network interface to a VM."""
    with self._lock:
      self.attached_vm_id = vm.id
      if self.attached_vm_id not in AwsNetworkInterface.vm_devices:
        AwsNetworkInterface.vm_devices[self.attached_vm_id] = set(
            range(1, NUM_NETWORK_INTERFACES[vm.machine_type]))
      self.device_letter = min(
          AwsNetworkInterface.vm_devices[self.attached_vm_id])
      AwsNetworkInterface.vm_devices[self.attached_vm_id].remove(
          self.device_letter)

    attach_cmd = util.AWS_PREFIX + [
        'ec2',
        'attach-network-interface',
        '--network-interface-id=%s' % self.id,
        '--instance-id=%s' % self.attached_vm_id,
        '--device-index=%s' % self.device_letter]
    logging.info('Attaching AWS ENI %s. This may fail if the device is not '
                 'ready, but will be retried.', self.id)
    stdout, _ = util.IssueRetryableCommand(attach_cmd)
    response = json.loads(stdout)
    self.attachment_id = response['AttachmentId']

  def Detach(self):
    """Detaches the network interface from a VM."""
    detach_cmd = util.AWS_PREFIX + [
        'ec2',
        'detach-network-interface',
        '--attachment-id=%s' % self.attachment_id]
    util.IssueRetryableCommand(detach_cmd)

    with self._lock:
      assert self.attached_vm_id in AwsNetworkInterface.vm_devices
      AwsNetworkInterface.vm_devices[
          self.attached_vm_id].add(self.device_letter)
      self.attached_vm_id = None
      self.device_letter = None

  def GetDeviceName(self):
    """Returns the name of the device inside the VM."""
    return 'eth%s' % self.device_letter
