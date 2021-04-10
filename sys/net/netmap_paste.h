#ifndef NETMAP_PASTE_H
#define NETMAP_PASTE_H

static const uint64_t NS_PST_FD_MASK = 0x000000ffffffff00;
static const int NS_PST_FD_SHIFT = 8;
static const uint64_t NS_PST_OFST_MASK = 0x00ffff0000000000;
static const int NS_PST_OFST_SHIFT = 40;

static inline int32_t
nm_pst_getfd(struct netmap_slot *slot)
{
	return (int32_t)((slot->ptr & NS_PST_FD_MASK) >> NS_PST_FD_SHIFT);
}

static inline void
nm_pst_setfd(struct netmap_slot *slot, int32_t fd)
{
	slot->ptr = (slot->ptr & ~NS_PST_FD_MASK ) |
		    (( (uint64_t)fd << NS_PST_FD_SHIFT) & NS_PST_FD_MASK);
}

static inline uint16_t
nm_pst_getdoff(struct netmap_slot *slot)
{
	return (uint16_t)
	       ((slot->ptr & NS_PST_OFST_MASK) >> NS_PST_OFST_SHIFT);
}

static inline void
nm_pst_setdoff(struct netmap_slot *slot, uint16_t ofst)
{
	slot->ptr = (slot->ptr & ~NS_PST_OFST_MASK) |
		    (( (uint64_t)ofst << NS_PST_OFST_SHIFT) & NS_PST_OFST_MASK);
}

static inline void
nm_pst_reset_fddoff(struct netmap_slot *slot)
{
	slot->ptr = (slot->ptr & ~(NS_PST_FD_MASK | NS_PST_OFST_MASK));
}
#endif /* NETMAP_PASTE_H */
