all:
	( cd target; $(MAKE) )
	( cd setup; $(MAKE) )

clean:
	( cd target; $(MAKE) clean )
	( cd setup; $(MAKE) clean )
