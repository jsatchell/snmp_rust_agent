# Notes on SMI Tables

This is my simplified understanding of tables for SNMP.

The relevant RFCs are 2578 and 2579. 

Some tables are read-only, and row creation is controlled by something outside the Agent.

Others allow row creation. For this to work, there needs to be a column with type RowStatus, and
at least one other column that is used as an index. Indices can use multiple columns, and even data from other tables. And there can be a range of other columns, some or all of which have default values.

In the easiest case to visualise, a Set operation arrives with at least two varbinds in it - one for the RowStatus column, with value perhaps CreateAndGo for simplicity, and an oid that consists of the table base plus the RowStatus column plus an unused but valid index value. So if table base is XX, and we have column 1 (index, integer) column 2 (OctetString) and Column 3 Rowstatus.