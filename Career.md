# My Resume


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
* The NDVI works by measuring the ratio of visible light vs near infrared light (0.7-1.1 $\mu$m ).
* So I am trying to get inferences from the survey questions and images themselves, and then test those against the results of the MODIS data and the farmer's estimation of the land's carrying capacity.
* When the researchers originally started having issues with the dataset, they tried to get mechanical turks to rate the carrying capacity. This is another questionably accurate source of data but another thing to use for truth checking and to come up with ideas.
* To start I created an efficient way to preview a few random images from whatever subset of the data I select without downloading all 120,000.
* Then I created subsets of the data based on seemingly consistent and inconsistent answers. I created a 'score' for answers which suggest higher carrying capacity, and another score which is for variables which suggest lower carrying capacity. for example green grass and dense grass, high carrying capacity and lots of animals, etc. Images with inconsistent tags do turn out to be more likely junk data, but most images have some "negative" and some "positive" indicators, meaning that this is only good for identifying some certain bad images.
* We initially tried using a basic tensorflow example to predict carrying capacity, which took a long time and didnt work at all. Then we tried to use inception just to see whether it could recognize trees accurately. This didn't work very well.
* Finally, I've started trying with some cleaned up subsets of the data to run randomforest classifiers and then inspect which variables most impact carryingcapacity. This has given us more information than anything so far, so I'm going to keep going down this path by trying different algorithms and other ways to use the survey data to infer what is in the pictures or what the satellite says.

## Cyber Insurance Presentation

1. People need to do the cheapest and easiest thing first because a lot of attorneys have no time or desire to learn about cybersecurity. This starts with basically awareness: having security policies, permissions, knowing what devices are on the network, having a clean desk, doing data inventory, setting permissions, etc.
2. GDPR AND CalCPA are coming, and what this means
3. Cyberinsurance and how to shop for it to help protect you against regulation
4. Further resources, checklists and where to go if you need more help.



## Freelance Work

## SIC

## Evolve

## College

# Questions for CyberCube

1. What type of role exactly would this be? Cyber, Data, Risk, or a combination?

2. What should I study for the next interview?

3. Can I ask you some questions I had for this upcoming presentation? Would you prefer to do that a different time?

4. Where does an organization's security posture come in to making Insurance decisions about the client?

Questions from the At-Bay Calculator

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
