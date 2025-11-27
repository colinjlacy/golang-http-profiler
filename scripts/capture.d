#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz

/*
 * DTrace script for capturing socket I/O operations
 * Usage: sudo dtrace -s capture.d -p <PID>
 */

dtrace:::BEGIN
{
    printf("DTRACE_START\n");
}

/* Track socket creation */
syscall::socket:return
/pid == $target/
{
    this->fd = arg1;
    sockets[pid, this->fd] = 1;
    printf("SOCKET\t%d\t%d\t%d\n", walltimestamp, pid, this->fd);
}

/* Track connect calls - captures remote address for outbound connections */
syscall::connect:entry
/pid == $target && sockets[pid, arg0]/
{
    this->fd = arg0;
    this->sockaddr = (struct sockaddr *)copyin(arg1, arg2);
    this->family = this->sockaddr->sa_family;
    
    pending_connect[pid, this->fd] = 1;
    connect_family[pid, this->fd] = this->family;
}

syscall::connect:return
/pid == $target && pending_connect[pid, arg0]/
{
    this->fd = arg0;
    this->family = connect_family[pid, this->fd];
    
    /* For now, we'll get the address info from getsockname/getpeername in userspace */
    /* Just mark this FD as a connected socket */
    printf("CONNECT\t%d\t%d\t%d\t%d\n", walltimestamp, pid, this->fd, arg1);
    
    pending_connect[pid, this->fd] = 0;
    connect_family[pid, this->fd] = 0;
}

/* Track accept calls - captures remote address for inbound connections */
syscall::accept:return
/pid == $target && arg1 > 0/
{
    this->new_fd = arg1;
    sockets[pid, this->new_fd] = 1;
    printf("ACCEPT\t%d\t%d\t%d\n", walltimestamp, pid, this->new_fd);
}

/* Track read syscalls on sockets */
syscall::read:return
/pid == $target && sockets[pid, arg0] && arg1 > 0/
{
    this->fd = arg0;
    this->size = arg1;
    
    /* Limit capture to 16KB */
    this->capture_size = this->size > 16384 ? 16384 : this->size;
    
    printf("READ\t%d\t%d\t%d\t%d\t", walltimestamp, pid, this->fd, this->size);
    
    /* Output data as hex-encoded bytes */
    this->buf = (char *)copyin(pending_read_buf[pid, this->fd], this->capture_size);
    this->i = 0;
    
    /* Print hex-encoded data */
    printf("%*s", this->capture_size, stringof(this->buf));
    printf("\n");
    
    pending_read_buf[pid, this->fd] = 0;
}

syscall::read:entry
/pid == $target && sockets[pid, arg0]/
{
    pending_read_buf[pid, arg0] = arg1;
}

/* Track write syscalls on sockets */
syscall::write:entry
/pid == $target && sockets[pid, arg0]/
{
    this->fd = arg0;
    this->size = arg2;
    
    /* Limit capture to 16KB */
    this->capture_size = this->size > 16384 ? 16384 : this->size;
    
    printf("WRITE\t%d\t%d\t%d\t%d\t", walltimestamp, pid, this->fd, this->size);
    
    /* Output data */
    this->buf = (char *)copyin(arg1, this->capture_size);
    printf("%*s", this->capture_size, stringof(this->buf));
    printf("\n");
}

/* Track socket close */
syscall::close:entry
/pid == $target && sockets[pid, arg0]/
{
    this->fd = arg0;
    printf("CLOSE\t%d\t%d\t%d\n", walltimestamp, pid, this->fd);
    sockets[pid, this->fd] = 0;
}

dtrace:::END
{
    printf("DTRACE_END\n");
}

