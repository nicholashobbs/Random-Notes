# WAYS TO RELAX

* slow down when you are speaking
* squeeze thighs or legs to stop shaking
* lean forward and stay dynamic
* show your hands
* make it about them
* listen very carefully
* breathe deeply - 4 seconds in, hold, out, hold.
* imagine yourself up in the canyon behind tom's house where you saw the moose with patch
* if it doesn't work out its not your fault - these people want this to work just like you do.


# My Message

First and foremost, I want to communicate that I am really passionate about statistics, cybersecurity, and solving hard problems as a part of a team.

## Top Points to Make To Everyone

1. Humility & Honesty - Admit things that you don't know. Answer questions as honestly as possible. Have practiced answers to hard questions, but tell the absolute truth unless you have a very practiced line. I'm a beginner at both cybersecurity and at data science.
2. I am first and foremost interested in the idea of dealing with and thinking about risk. This started with really enjoying statistics and probability, then I read the book Against The Gods, which had a big impact on me. Later on I read Antifragile, which further deepened my interest in thinking about risk and tied together a number of my interests.  Xi jinping said china needs to be ready for black swans and gray rhinos
3. Modeling cyber risk seems like one of the most relevant and difficult things you could try to predict right now.
4. Identify the single thing that they are trying to find out about you - whether you're likable, how well you know something, etc.
5. Identify their primary interest in this job - what makes them love studying cyber risk - assume that everyone there does
6. I think that eventually all insurance will be cyber.


## Deflection/Backup Strategy

* Not something I prepared for. I tried to think of everything but I didn't expect that. Can I think on it?

* I didn't really prepare technically since I wasn't sure what to focus on. I'd love to answer your question a different way or learn to use that technology though.

* For evolve - i really enjoyed it and learned a great deal, met some amazing people

* for my recent work - I haven't had any paid freelance work but ive been working on cv project, cyberinsurance presentation, and getting ready for this interview

* i had enough work for a few months but it is stressful to find new work.

* The real reason I want a full time job is to learn more by working with the same team for a long time with people who know a lot more than me. I can't think of a better place than here because I'm interested in what everyone is doing.


## What Would I Do If I Got the Job to Advance ASAP

Be there close to first every day
Finish work that's given to you as quickly as possible - show respect for the person who gave you the work by: finishing it thoroughly, asking for feedback, making changes, and getting it done.
Search for and ask for new work when you need it.
Devote time and energy every day to office politics
Track every person and the state of your relationship - look for an fix weak spots
Look for everyone's specialty
Learn as much as possible from them politely
Write it all down - create documentation and improve existing documentation as much as you can
Listen to so good they cant ignore you again

Show up fascinated by everyone at the company and how they ended up there. Stay quiet and respectful, but reach out consistenly to everyone to learn and try to help.
Look for how you can help people at all times.
Let people talk about themselves and when you identify the thing they want to talk about, pay attention and ask specific questions about it\

where do i dream of being in 5 years?

hopefully at cybercube which i imagine is very big by then?
maybe working in a foreign country, something i always wanted to do
maybe going to school
maybe trying to learn more about business and startups


# My Resume

"Consulting for several small businesses on cybersecurity - determining potential vulnerabilities, implementing security programs and developing strategies to manage regulation and cyber-risk long-term" - With several friends, we started talking to a number of small health-care clinics and a start-up car insurance company in Chicago to do security consulting. 'So far this hasn't really materialized, but we have spent a lot of time talking and thinking about it'

## CV Project

### Background

* This project involves trying to make sense of a dataset from ILRI in Kenya which has 120,000 geotagged cell phone pictures which are associated with survey data.
* The survey asked pastoralists to rate the carrying capacity of the land by asking how many cows could be fed by the available forage within 20 steps in every direction for one day.
* The survey then asked participants whether there were grass, shrubs or trees in the area and whether they had green, brown or no leaves. It also asked whether there were animals grazing, and how far away the nearest source of water was.

### Issues

* There are a number of issues with the data collected and the survey design. The images are poor quality and seem to have been processed somehow, although it's not clear how. Colors seem to be blended together in a strange way, as if the images have been compressed.
* Some of the pictures are of people, villages, or people holding up printed pictures. Some pictures are clearly geotagged wrong, indicating that they may have been uploaded from a different place than where they were taken.
* The way that herders were asked about carrying capacity is problematic. Participants were asked about an area within a 20 step radius, but the pictures only show one direction which may or may not be consistent with the carrying capacity rating.
* Some of the survey data is unintelligible. For example, there are certain rows which have a value 3 3 1 1 2 2 in a column where the possible values are 1 2 and 3. The survey app is based on OpenDataKit Collect, and it seems like these responses mean that someone checked and unchecked an option, resulting in 2 clicks. For now, I have just discarded these rows for the few experiments I have run, because there are not very many instances.

### Methodology

* The goal is to use survey data along with MODIS satellite data to try to find techniques which get close to the results of the NDVI (Normalized Difference Vegetation Index).
* The NDVI works by measuring the ratio of visible light(0.4-0.7 $\mu$m), which is strongly absorbed by chlorophyl for photosynthesis, vs near infrared light (0.7-1.1 $\mu$m), which is strongly reflected by the cell structure of leaves. $NDVI = \frac{NIR - Red}{NIR + Red}$
* So I am trying to get inferences from the survey questions and images themselves, and then test those against the results of the MODIS data and the farmer's estimation of the land's carrying capacity.
* When the researchers originally started having issues with the dataset, they tried to get mechanical turks to rate the carrying capacity. This is another questionably accurate source of data but another thing to use for truth checking and to come up with ideas.
* To start I created an efficient way to preview a few random images from whatever subset of the data I select without downloading all 120,000.
* Then I created subsets of the data based on seemingly consistent and inconsistent answers. I created a 'score' for answers which suggest higher carrying capacity, and another score which is for variables which suggest lower carrying capacity. for example green grass and dense grass, high carrying capacity and lots of animals, etc. Images with inconsistent tags do turn out to be more likely junk data, but most images have some "negative" and some "positive" indicators, meaning that this is only good for identifying some certain bad images.
* We initially tried using a basic tensorflow example to predict carrying capacity, which took a long time and didnt work at all. Then we tried to use inception just to see whether it could recognize trees accurately. This didn't work very well.
* Finally, I've started trying with some cleaned up subsets of the data to run randomforest classifiers and then inspect which variables most impact carryingcapacity. This has given us more information than anything so far, so I'm going to keep going down this path by trying different algorithms and other ways to use the survey data to infer what is in the pictures or what the satellite says.

## Freelance Work

database stuff - lots of transcripts, working for a company which is a contractor for the CFPB. They did document testing with a lot of people - basically interviewing them about student loan documents and how they interpreted them. They are trying to make the case that these documents were intentionally hard to understand.

I started by doing it mostly manually and as I worked learned to automate more and more of the process. Eventually I developed a procedure which saved a ton of time and got through the transcripts much more quickly.

Did about 80 transcripts and 300 hours.

There is a similar case coming up with credit card companies for which they may also want to convert word documents into access databases.

Digitizing forms for nutrition business and for the same company.

## SIC

First Star was starting an academy at the University of Utah and trying to get funding from the state government. I created a presentation which outlined some of the statistics from studies which compared similar states with different rules about what happens to foster youth after they age out of foster care. I then tried to estimate some of these costs and make the argument that investing in their college education upfront would save the government in the long run.

Other projects I worked on: JRI - utah association of counties wanted to know what happened to crime after this law was enacted. We did research which showed that drug crime had increased since JRI has passed, as they suspected, but not for the reason they thought. Incidentally, we also found an interesting trend where the geographic location of drug crime became increasingly concentrated as it increased.

## Evolve

Networking, Kali, Linux in General, Tools in Kali, Cybersecurity frameworks and fundamentals

An excellent introduction with lots of hands on experience. I met some really fascinating people - including Patrik, and they set me up with lots of interesting connections and interviews.

## UCAN

Started with scoping, talking to the client about what their concerns were and what they wanted to know about their networks. Their whole IT Team was the CIO, Director of IT, Sharepoint Administrator, and Network Administrator.

* We examined web interface in addition to over 2000 IP addresses on 8 subnets using nmap, Nessus, nikto, and other scanning tools
* Attempted to exploit vulnerabilities using various tools and resources in Kali Linux, including metasploit, searchsploit, Linux Exploit Suggester, Hydra, HashCat, and BeEF
* Created and sent phishing campaign to employees to determine vulnerability to social engineering attacks and promote phishing awareness
* Identified several critical vulnerabilities and unsecured network devices which would enable attackers to steal client data and compromise network integrity (possibility for eternalblue exploit, but nobody was able to do it)
* Found unsecured printers which had saved versions of everything they had printed
* Found possible cross site request forgery on asp.net website.

# Behavioral Questions

# Questions for CyberCube

This is where my really interesting questions can come from -
* what details should people be paying attention to when they buy cyber insurance?
* What details should insurers be paying attention to when they sell cyber insurance policies?
* What do you do about complacency once you sell somebody a policy?
* What is to stop them from investing less in certain security measures once they are insured?



* If you get the job, hit the ground running by taking an interest in each person you get the chance to talk to.


* For each person you talk to - What are you trying to find out about them and vice versa - how complementary are they, what are the differences.

* is there anything like a better driver discount in auto insurance - insurers put things in peoples cars, why not their own software to test peoples' systems?

* Whats the most interesting thing you've learned since working here
* why did you want to work here
* what interests you about cyber insurance
* anything you really didn't expect but found at the company or in the job
* how do you measure success
* does everyone work together at some point
* how much of work is collaborative
* what are paths for advancement
* can i help who i want if i have time
* what are educational benefits
* what do you think is most relevant for me to learn right now if i got this job - cs, stat, data, technologies, what.
* what technology do you work with most often

* ASK QUESTIONS about presentation -

* what do you think are the easiest and cheapest things an average company with no security thinkin should do to improve their situation

Is there a way for clients to know how their level of security relates to their rates? If they have to fill out a questionairre for example, would they be provided with suggestions on how to improve their security posture to reduce their premiums - it seems to price their risk level you have to assess them, at which point you might as well add more value by providing client with the results of the assesments

what is cheapest and most impactful - price vs security improvement


# On Their Website

* diverse, collaborative, passionate, and intelligent

* Team Collaboration, Openness and Trust, Intellectual Rigor, Passion for Excellence, Getting Things Done



## Cyber Risk Analyst Job Posting


* Conduct in-depth research at the crossroads of cyber security, insurance, and risk modeling
* Help design and build new analytical data models and/or enhance existing data models
* Provide analytical support to other team members
* Prepare static and dynamic data visualizations for use in internal and external contexts
* Work closely with products, analytics, and engineering team members

* Self-starter able to work well independently as well as in various team settings
* Intellectual curiosity, willingness to learn new skills, and ability to contribute ideas
* Excellent organizational and time management skills
* Eager to work in an agile environment
* An analytical mindset with problem-solving skills
* Excellent communications and presentation skills
* Experience working in one or more of the following industries & fields: cyber security, data science, risk modeling & management, and consulting
* Ideally familiarity with Python / R, relational databases (incl. SQL), big data frameworks (Spark / Hadoop), flat files and complex data types (JSON, XML, etc.), APIs, and Excel


what APIS have you worked with: NONE PROFESSIONALLY. some in personal projects sometimes - i tried to use twitter for sentiment analysis and wikipedia api for a game i was working on.

# Things to Know

## Python
pandas
numpy
seaborn
keras
tensorflow
nltk
beautifulsoup
supervised and unsupervised
feature extractions
pca
deep learning
static and dynamic data visualizations

## SQL
inner join is intersection, left/right outer join are intersection plus left or right

* `SELECT {cols} FROM {table} WHERE col = value AND/OR col = value`
* `GROUP BY {col}`
`HAVING`
* `ORDER BY {col}`
`UPDATE table SET col = value WHERE col = value`
`BETWEEN a AND b`
`IN(a,b,c)`

* views are like virtual tables
`CREATE VIEW name AS`

`JOIN col UPDATE`
`UPDATE table SET value`
* primary keys - the main way to keep track of individuals
* clustered non clustered index - ordered by whatever the index is vs having a separate index
* stored procedures - something you want to do repeatedly in sql
* joins - adding two tables together
* views - a statement which describes a virtual table stored in the database with a name


## Cybersecurity

**OSI Model** - physical, data link, network, transport, session, presentation, application

**TCP / IP Model** - application, transport, internet, link

**OWASP Top 10** - injection, broken authentication, sensitive data exposure, XXE, broken access control, security misconfiguration, XSS, insecure deserialization, using components with known vulnerabilities, insufficient logging and monitoring

**Diamond Model** - adversary , infrastructure/capability, victim

**Kill Chain** - Recon, Weaponization, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives

## Other

* Spark - the compute engine for hadoop. you can access data in cassandra, hive, etc.
* Hadoop - allows distributed processing of large data sets across clusters of computers
* cassandra - a type of database which automatically replicates data to multiple nodes with linear scalability
java
* aws ec2, s3, rds - cloud compute, storage, and data warehouse
* xml - extensible markup language
* json - javascript object notation
* docker - container platform
* kubernetes - container orchestration - automates deployment, scaling, and management of containerized applications
* scrum and agile - organized way to do iterative development



# Questions from the At-Bay Calculator

Customer & Employee Records or just Employee
* How many people were affected?
* What types of records? PII? Credit Card? Health?
* How were records breached? Error, Leak, Device Theft, Hack
* Do you store the mailing addresses for breached records?
* Have you publicly disclosed another breach in the last 24 months?
* How would you estimate the level of complexity of your network?
* How big of a news story would this breach be? no news, regional news, national news
* How would you estimate your security controls compared to industry best practices? Average, above, or below
* Are you based out of California?

Costs:
* Breach Coach
* Forensics
* Crisis Management
* Notification
* Call Center
* Credit Monitoring
* PCI Fines and Assessments
* Regulatory Fines and Defense
* Class Action Settlements and Defense
