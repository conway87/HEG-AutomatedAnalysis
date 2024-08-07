


- 🤖 Run an Automated Analysis on the .csv outputs of your **[HEG](https://github.com/conway87/HEG-3.0)** / **[BeefEater](https://github.com/conway87/HEG-BeefEater)**
- ⏱️ Reduce time and effort needed to analyse those .csv files by hand.
- 📊 Output analysis to a .xlsx file with visually intuitive formatting.
- 🔍 Colourised items make it easy to quickly lock in on what you need and slice'n dice information easily
- 🕵️‍♂️ IOCs, interesting items, script operations, cleanup operations are automagically tagged and annotated.
- 🔥 Get straight to the useful items, ignore the noise.

<br>

## Example

<br>

**.csv before AA** - Thousands of lines of logs that are difficult to work with.

<br>

![Before](https://github.com/user-attachments/assets/3ae157b1-7252-45c2-adac-c81e5d4fedc5)

<br>

**After AA** - File is open at same position as above screenshot - but this time colour coding and annotations make it easier and much faster to see whats happening at a glance.

<br>

![After](https://github.com/user-attachments/assets/df26236a-f693-44ce-ad54-97f16393c702)


<br>

## Getting Started
1. Install Python
&nbsp;

2. Install following libraries:
   
    * pip install pandas
    * pip install jinja2
    * pip install openpyxl


3. Download the correct .py file for the version of HEG you plan to run. Standard HEG or BeefEater.
4. Drop the .py into Logs directory where the .csv files were generated.
5. From CMD.exe navigate to that directory and then run the .py file.

<br>

## Note on Sysmon

AA has been tuned to work best on **[Olaf Hartongs sysmon implementation](https://github.com/olafhartong/sysmon-modular)**. Specifically the sysmon with file delete configuration. AA should work on most about any sysmon deployments with little issue - but best results will come from that implementation.



