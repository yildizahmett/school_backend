from sqlalchemy import text, engine

selected_filter = {}
selected_table_name = "employees"

exec_str = f"select * from {selected_table_name} where "

for key, value in selected_filter.items():
    exec_str += "("
    for i in value:
        exec_str += key + " = \"" + str(i) + "\" or "
    exec_str = exec_str[:-4] + ") and "
exec_str = exec_str[:-5]

print()

with engine.connect() as con:
    result = con.execute(text(exec_str))
    employees = result.fetchall()

