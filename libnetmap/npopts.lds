SECTIONS
{
	.npopts ALIGN(16) : {
		npopts_start = .;
		*(.npopts)
		npopts_end = .;
	}
	.npkeys ALIGN(16) : {
		npkeys_start = .;
		*(.npkeys)
		npkeys_end = .;
	}
}
