ALTER TABLE certificates ADD COLUMN serial_number numeric(50);
UPDATE certificates SET serial_number=id WHERE serial_number=NULL;
