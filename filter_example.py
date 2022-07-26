exec_str = "select * from employees where "
for key, value in selected_filter.items():
    exec_str += "("
    for i in value:
        exec_str += key + " = \"" + str(i) + "\" or "
    exec_str = exec_str[:-4] + ") and "
exec_str = exec_str[:-5]

with engine.connect() as con:
    result = con.execute(text("select * from employees where name='Kerem'"))
    employees = result.fetchall()

print(employees)