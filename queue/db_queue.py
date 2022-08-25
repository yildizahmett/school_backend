from scripts.util import engine
from datetime import datetime

def search_talent_log(selected_filter, filtered_by):
    date = datetime.now()
    date = date.strftime('%Y-%m-%d %H:%M:%S')
    query = f'insert into search(filter_content, filter_type, filtered_by, filter_date) values '
    for key, value in selected_filter.items():
        for v in value:
            query += f'(\'{v}\', \'{key}\', {filtered_by}, \'{date}\'),'
    query = query[:-1]
    query += ";"

    with engine.connect() as con:
        con.execute(query)
        con.close()