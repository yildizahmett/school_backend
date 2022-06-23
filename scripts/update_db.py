from models import db
try:
    db.drop_all()
    print('Dropped all tables.')
except:
    pass
db.create_all()
print('Created all tables.')

"""const mockData = {
	education: [
		{
			school: "University of California, Berkeley",
			degree: "Bachelor of Science",
			department: "Computer Science",
			graduation: "2019",
		},
		{
			school: "University of California, Berkeley",
			degree: "Bachelor of Science",
			department: "Computer Science",
			graduation: "2019",
		},
	],
	jobs: [
		{
			company: "Google",
			title: "Software Engineer",
			sector: "Software",
			start: "2019",
			end: "2020",
			description: "My description text",
			location: "San Francisco, CA",
		},
		{
			company: "Google",
			title: "Software Engineer",
			sector: "Software",
			start: "2019",
			end: "2020",
			description: "",
			location: "San Francisco, CA",
		},
	],
	projects: [
		{
			name: "Project 1",
			description: "My description text",
			sector: "Software",
			company: "Google",
			start: "2019",
			end: "2020",
			location: "San Francisco, CA",
			description: "My description text",
		},
		{
			name: "Project 2",
			description: "My description text",
			sector: "Software",
			company: "Google",
			start: "2019",
			end: "2020",
			location: "San Francisco, CA",
			description: "My description text",
		},
	],
	languages: [
		{
			name: "English",
			level: "Native",
		},
		{
			name: "Spanish",
			level: "Basic",
		},
	],
};"""