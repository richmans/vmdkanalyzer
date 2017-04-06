import array
import sys
import struct
import os

SECTOR_SIZE = 512

# this will try to parse sparse vmdk files and identify any integrity issues
# based on    https://www.vmware.com/support/developer/vddk/vmdk_50_technote.pdf
# inspired by https://github.com/qemu/qemu/blob/master/block/vmdk.c

def sizemb(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)
    
class VmdkParser:
  def __init__(self, i, filesize):
    self.i = i
    self.errors = []
    self.filesize = filesize
    self.blocks = [None] * int(filesize / SECTOR_SIZE)
    
  def d(self, msg, offset = -1):
    if offset == -1: 
      offset = self.i.tell()
    print("[%12d] %s" % (offset, msg))
  
  def e(self, msg, offset = -1):
    if offset == -1: 
      offset = self.i.tell()
    msg = "[%12d] ERROR %s" % (offset, msg)
    self.errors.append(msg)
    print(msg)
    
  def parse_magic(self):
    self.magic = self.i.read(4)
    if self.magic == b"COWD":
      self.d("Version 3 header found")
      self.version = 3
    elif self.magic == b"KDMV":
      self.d("Version 4 header found")
      self.version = 4
    else:
      self.d("Invalid magic string %s" % self.magic)
      raise Exception("Could not determine file type")
  
  def parse_v3_header(self):
    hdr = struct.unpack("<10I", self.i.read(40)) # read 10 32bit unsigned LE ints
    self.subversion = hdr[0]
    self.flags = hdr[1]
    self.capacity = hdr[2]
    self.granularity = hdr[3]
    self.gd_offset = hdr[4]
    self.gd_size = hdr[5]
    self.used_sectors = hdr[6]
    self.gt_size = 4096
    
  def parse_v4_header(self):
    hdr = struct.unpack("<II4QI3Q5cH", self.i.read(75)) # read v4 header structure
    self.subversion = hdr[0]
    self.flags = hdr[1]
    self.capacity = hdr[2]
    self.granularity = hdr[3]
    self.gd_offset = hdr[7]
    self.gt_size = hdr[6]
    # calculation from https://github.com/qemu/qemu/blob/master/block/vmdk.c:688
    l1_sectors = self.gt_size * self.granularity
    self.gd_size = int((self.capacity + l1_sectors - 1) / l1_sectors) 

  def print_header(self):
    self.d("-- Header info --")
    self.d("Capacity %d blocks (%.2f gb)" % (self.capacity, float(self.capacity)*SECTOR_SIZE / (1024*1024*1024)))    
    self.d("Grain size %d" % self.granularity)
    self.d("GD Offset %d" % self.gd_offset)
    self.d("GD Size %d" % self.gd_size)
    self.d("GT Size %d" % self.gt_size)
    self.d("Filesize %d" % self.filesize)
    self.d("----")
  
  def parse_gd(self):
    self.reserve_block(0, 0, 0)
    self.reserve_block(1, 0, 0)
    self.gtes = 0
    self.gts = 0
    o=self.gd_offset * SECTOR_SIZE
    self.i.seek(o)
    self.gd = struct.unpack("<%dI" % self.gd_size, self.i.read(self.gd_size * 4))
    ctr = 0
    for gde in self.gd:
      if gde == 0: 
        ctr += 1
        continue
      self.d("GDE %d:%d" % (ctr,gde), o + ctr * 4)
      for i in range(0, 4):
        self.reserve_block(gde + i, ctr, 0)
      self.parse_gt(ctr, gde)
      ctr+=1
  
  def parse_gt(self, gd, gde):
    o = gde * SECTOR_SIZE
    self.i.seek(o)
    gt = struct.unpack("<%dI" % self.gt_size, self.i.read(self.gt_size * 4))
    ctr = 0
    self.gts += 1
    for gte in gt:
      gteo = o + ctr * 4
      if gte == 0: 
        ctr +=1
        continue
      self.gtes += 1
      self.d(" GTE %d,%d:%d" % (gd,ctr,gte), gteo)
      if gte > self.capacity:
        self.e("gte %d out of bounds" % gte, gteo)
      for i in range(0, self.granularity):
        self.reserve_block(gte + i, gd, ctr)
      ctr += 1
      
  
  def reserve_block(self, idx, gd, gt):
    #print("Reserving %d for %d,%d" %(idx, gd,gt))
    if self.blocks[idx] != None:
      self.e("Block %d already reserved by %d,%d" % (idx, self.blocks[idx][0], self.blocks[idx][1]))
    else:
      self.blocks[idx] = [gd, gt]

  def check_blocks(self):
    self.used_blocks = 0
    for idx, b in enumerate(self.blocks):
      if b == None:
        #self.d("Free block %d" % idx, idx * SECTOR_SIZE)
        pass
      else:
        self.used_blocks += 1
    expect_used = self.gtes + self.gts * 4 + 2
    if self.used_blocks != expect_used:
      self.e("Expected %d blocks used, found %d" % (expect_used, self.used_blocks))
      
    if self.used_sectors != None and self.used_sectors != expect_used:
      self.e("Expected %d blocks used, found %d in v3 header" % (expect_used, self.used_sectors))
      
  def parse_header(self):
    if self.version == 4:
      self.parse_v4_header()
    elif self.version == 3:
      self.parse_v3_header()
    else:
      raise Exception("No header found")    
      
  def parse(self):
    self.parse_magic()
    self.parse_header()
    self.print_header()
    self.parse_gd()
    self.check_blocks()
    filesize_estimation = self.gtes * SECTOR_SIZE * self.granularity
    self.d("Parsing complete: %d grains (%s), %d gts, filesize %s, %d used_blocks, %d errors" % (self.gtes, sizemb(filesize_estimation), self.gts, sizemb(self.filesize), self.used_blocks, len(self.errors)))
    
def main(filename):
  inputfile = None
  try:
    fsize = os.stat(filename).st_size
    inputfile = open(filename, 'rb')
    
  except:
    print("Can't open file")
    sys.exit(1)
  p = VmdkParser(inputfile, fsize)
  try:
    p.parse()
  except Exception as e:
    print(e.message)


if (len(sys.argv) < 2): 
  print("Please give me a nice vmdk file!")
  sys.exit(1)
main(sys.argv[1])
