/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell
 */

#ifndef __INCLUDE_VIRTIO_H__
#define __INCLUDE_VIRTIO_H__

/** Device feature lower 32 bits */
#define VIRTIO_F_ANY_LAYOUT 27

/** Device feature higher 32 bits */
#define VIRTIO_F_VERSION_1	   32
#define VIRTIO_F_IOMMU_PLATFORM	   33
#define VIRTIO_F_RING_PACKED	   34
#define VIRTIO_F_IN_ORDER	   35
#define VIRTIO_F_ORDER_PLATFORM	   36
#define VIRTIO_F_SR_IOV		   37
#define VIRTIO_F_NOTIFICATION_DATA 38

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM	    0  /* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM	    1  /* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MTU	    3  /* Initial MTU advice. */
#define VIRTIO_NET_F_MAC	    5  /* Host has given MAC address. */
#define VIRTIO_NET_F_GUEST_TSO4	    7  /* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6	    8  /* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN	    9  /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO	    10 /* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4	    11 /* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6	    12 /* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN	    13 /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO	    14 /* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF	    15 /* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS	    16 /* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ	    17 /* Control channel available */
#define VIRTIO_NET_F_CTRL_RX	    18 /* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN	    19 /* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA  20 /* Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21 /* Guest can announce device on the network */
#define VIRTIO_NET_F_MQ		    22 /* Device supports Receive Flow Steering */
#define VIRTIO_NET_F_CTRL_MAC_ADDR  23 /* Set MAC address */
#define VIRTIO_NET_F_RSS	    60 /* RSS supported */

/* Device set linkspeed and duplex */
#define VIRTIO_NET_F_SPEED_DUPLEX 63

/** This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT 48
/** This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE 50
/** This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT 52
/** This flag means the descriptor was made available by the driver */
#define VIRT_PACKED_RING_DESC_F_AVAIL (1UL << 55)
/** This flag means the descriptor was used by the device */
#define VIRT_PACKED_RING_DESC_F_USED (1UL << 63)
#define VIRT_PACKED_RING_DESC_F_AVAIL_USED                                                         \
	(VIRT_PACKED_RING_DESC_F_AVAIL | VIRT_PACKED_RING_DESC_F_USED)

#define VIRTIO_NET_CTRL_MQ		4
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET 0

#define VIRTIO_NET_OK  0
#define VIRTIO_NET_ERR 1

/** Virtio device status */
enum virtio_dev_status {
	/** Virtio device status reset */
	VIRTIO_DEV_RESET = 0,
	/** Virtio device status acknowledge */
	VIRTIO_DEV_ACKNOWLEDGE = 1,
	/** Virtio device status driver */
	VIRTIO_DEV_DRIVER = 2,
	/** Virtio device status OK */
	VIRTIO_DEV_DRIVER_OK = 4,
	/** Virtio device features OK */
	VIRTIO_DEV_FEATURES_OK = 8,
	/** Virtio device needs reset */
	VIRTIO_DEV_NEEDS_RESET = 64,
	/** Virtio device failed */
	VIRTIO_DEV_FAILED = 128,
};

/** Virtio packet descriptor */
struct vring_packed_desc {
	/** Buffer address */
	uint64_t addr;
	/** Length */
	uint32_t len;
	/** Buffer ID */
	uint16_t id;
	/** Descriptor flags */
	uint16_t flags;
};

#endif /* __INCLUDE_VIRTIO_H__ */
