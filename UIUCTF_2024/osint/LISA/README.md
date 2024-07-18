# UIUCTF

## OSINT - Long Island Subway Authority

This is a 3 part OSINT challenge.

### Part 1

<img title="" src="Part1/Part1.png" alt="" width="853" data-align="center">To start, I searched **"Long Island Subway Authority"** on **Instagram**, which gave me this page:

<img title="" src="Part1/InstagramSearch.png" alt="" width="556"><img title="" src="Part1/InstagramAccount.png" alt="" width="496">

The posts on Instagram have nothing much, but there even exists a **Threads** link in the Instagram profile bio, which leads to the threads page:

<img title="" src="Part1/ThreadsAccount.png" alt="" width="364" data-align="center">

Scrolling through the comments of the threads by them - **First Thread**, I came across the flag:

<img title="" src="Part1/Part1Flag.png" alt="" width="427" data-align="center">

Which gives the flag: ***uiuctf{7W1773r_K!113r_321879}***.

### Part 2

<img title="" src="Part2/Part2.png" alt="" data-align="center" width="864">

Using data from the first challenge, I noticed a **LinkedIn** account in the **bio of the Threads account**. Going to the LinkedIn account, I got this page:

<img title="" src="Part2/LinkedInAccount.png" alt="" data-align="center" width="513">

Navigating to the skills, I got:

<img title="" src="Part2/Skills.png" alt="" data-align="center" width="523">

Viewing the one endorsement and visiting their profile:<img title="" src="Part2/Endorsement.png" alt="" width="589" data-align="center"><img title="" src="Part2/UIUCChan.png" alt="" data-align="center" width="722">

The flag is in the bio: ***uiuctf{0M160D_U1UCCH4N_15_MY_F4V0r173_129301}***.

### Part 3

<img title="" src="Part3/Part3.png" alt="" data-align="center" width="829">

Using data collected from the second challenge, I noticed a **Contact Info** section in the **bio of the LinkedIn page of UIUC Chan**.

<img title="" src="Part3/ContactUIUC.png" alt="" data-align="center" width="779">

Opening the Spotify account, we get the following page:

<img title="" src="Part3/SpotifyAccount.png" alt="" data-align="center" width="597">

Now, if I searched for the playlists under UIUC Chan and the followers' list, I tried to get some data but did not find it. But as soon as I clicked the follow button, I got a notification under the friend activity.

<img title="" src="Part3/FriendActivity.png" alt="" data-align="center" width="802">

Clicking on the playlist gives the following:

<img title="" src="Part3/Part3Flag.png" alt="" width="788" data-align="center">

The flag is in the playlist info: ***uiuctf{7rU1Y_50N65_0F_7H3_5UMM3r_432013)***.

> [!NOTE]
> 
> ## This writeup was possible by team effort.
> 
> I initially couldn't find the Instagram account from a Google search (I found it later through an Instagram search 😋).

## Insights:

On doing a simple Google search, we can't find the Instagram account:

<img title="" src="Falied/SimpleSearch.png" alt="" data-align="center" width="714">

Even on doing a "dork" search, we don't get much:

<img title="" src="Falied/AdvancedSearch.png" alt="" data-align="center" width="785">

This is because these websites are a part of the **Deep Web**. Even though these challenges may not require you to create an account, it is better to check this as a logged-in user because then you will have more viewing features without limited access to the websites.

Use the links to read more about the [**Deep Web**](https://en.wikipedia.org/wiki/Deep_web) and [**Dorking**]([Google hacking - Wikipedia](https://en.wikipedia.org/wiki/Google_hacking)).

# Author: Mohana Evuri
